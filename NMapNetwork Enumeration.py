#!/usr/bin/env python3
"""
Comprehensive interactive Nmap runner
- Grouped menus for scan types, NSE selection, ports, timing, output and misc
- Simple compatibility checks and auto-corrections
- Validates target as single IP / CIDR / hostname
- Requires user confirmation and a legal use acknowledgement before running scans

Note: Use only on systems you own or are authorized to test.
"""

import argparse
import subprocess
import sys
import os
import ipaddress
import re
import json
import textwrap
from datetime import datetime
from shutil import which
import shlex
import traceback

# Optional color support
try:
    from colorama import init as _cinit, Fore, Style
    _cinit(autoreset=True)
except Exception:
    class _C:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    Fore = Style = _C()

if which("nmap") is None:
    print("nmap not found in PATH. Install nmap before running this script.")
    sys.exit(1)

# Define option groups
SCAN_TYPES = {
    "1": ("TCP SYN scan", "-sS", "Stealthy SYN (half-open) scan used by professionals for fast, low-noise host enumeration."),
    "2": ("TCP Connect scan", "-sT", "Full TCP connect scan — reliable without raw socket privileges; noisier on IDS."),
    "3": ("UDP scan", "-sU", "UDP service discovery; slower and often requires retries and tuning for reliable results."),
    "4": ("SCTP INIT scan", "-sY", "SCTP INIT chunk scan for SCTP-based services when applicable."),
    "5": ("Ping scan (discovery)", "-sn", "Host discovery only: determines live hosts without port probes (useful for large networks)."),
}

NSE_CATEGORIES = {
    "1": ("default", "Low-risk scripts used for baseline discovery and service enumeration."),
    "2": ("discovery", "Active discovery and information-gathering scripts (service banners, endpoints)."),
    "3": ("auth", "Authentication-related checks; may interact with login mechanisms — use caution."),
    "4": ("vuln", "Non-exploit vulnerability checks (detection); can be intrusive and should be authorized."),
    "5": ("exploit", "Exploit-capable scripts — potentially damaging; require explicit, auditable authorization."),
    "6": ("safe", "Conservative scripts with low impact, suitable for early recon phases."),
    "7": ("all", "Runs the full script corpus; usually only for controlled, laboratory environments."),
}

PORT_OPTIONS = {
    "1": ("Top 1000", "--top-ports 1000", "Scan nmap's top 1000 most common ports — good for quick triage."),
    "2": ("Default", "", "Let nmap decide port list heuristically (fast and lightweight)."),
    "3": ("Custom range", "-p", "Explicit port list or ranges (e.g., 1-65535 or 22,80,443) for comprehensive scans."),
}

TIMING_OPTIONS = {
    "1": ("Paranoid (T0)", "-T0", "Extremely slow/stealthy — used when avoiding detection is the highest priority."),
    "2": ("Sneaky (T1)", "-T1", "Cautious timing to reduce noise and false positives on IDS/IPS."),
    "3": ("Polite (T2)", "-T2", "Balanced throughput for constrained networks or sensitive environments."),
    "4": ("Normal (T3)", "-T3", "Default template — reliable baseline for most environments."),
    "5": ("Aggressive (T4)", "-T4", "Higher speed for fast enumeration on trusted or lab networks."),
    "6": ("Insane (T5)", "-T5", "Maximum speed; only on high-bandwidth, controlled networks."),
}

OUTPUT_OPTIONS = {
    "1": ("Normal", "-oN", "Human-readable report file for notes and review."),
    "2": ("XML", "-oX", "Structured XML output for automated parsing and ingestion into tools."),
    "3": ("Grepable (legacy)", "-oG", "Quick machine-friendly output for legacy parsing workflows."),
    "4": ("All formats", "-oA", "Produce all common formats (Nmap, XML, grepable) for comprehensive artifacts."),
}

MISC_OPTIONS = {
    "1": ("Service/version detection", "-sV", "Active service/version probing to fingerprint services (useful for vuln mapping)."),
    "2": ("OS detection", "-O", "Attempt OS fingerprinting; noisy and may be blocked by modern devices."),
    "3": ("Traceroute", "--traceroute", "Capture network path; useful for situational awareness during engagements."),
    "4": ("Disable host discovery (-Pn)", "-Pn", "Skip host discovery and treat targets as up (useful when ICMP is filtered)."),
    "5": ("Fragment packets", "-f", "Packet fragmentation to attempt bypassing simplistic filters (use responsibly)."),
    "6": ("Spoof MAC", "--spoof-mac", "Spoof MAC address (value required; 'random' allowed)."),
}

CONFIRM_TEXT = (
    "By running scans you affirm that you have authorization to test the specified targets.\n"
    "Unauthorized scanning may be illegal. Proceed? (yes/no): "
)

# State
state = {
    "scan_type": None,
    "nse": set(),
    "port_mode": "Default",
    "port_arg": "",
    "timing": None,
    "output": None,
    "output_name": "",
    "misc": set(),
    "misc_values": {},
    "target": "",
    "operator": "",
    "roe_acknowledged": False,
    "advanced_flags": "",
    "decoy": "",
    "source_port": "",
    "pcap_enabled": False,
    "pcap_file": "",
    "pcap_file_name": "",
    "pcap_iface": "",
    "pcap_filter": "",
    "trace_enabled": False,
    "dry_run": False,
}

# Helpers
def colored(s, color=Fore.CYAN):
    return f"{color}{s}{Style.RESET_ALL}" if getattr(Fore, 'CYAN', None) else s


def clear_screen():
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
    except Exception:
        pass


def build_nmap_preview():
    """Build a preview nmap command from current state (safe, non-executing).
    This mirrors the command-assembly used at runtime but avoids prompts and confirmations.
    """
    cmd = ["nmap"]
    if state.get("scan_type"):
        cmd.append(state["scan_type"][1])
    # ports
    if state.get("port_mode") == "Top 1000":
        cmd.extend(["--top-ports", state.get("port_arg") or "1000"])
    elif state.get("port_mode") == "Custom range":
        p = state.get("port_arg") or ""
        cmd.extend(["-p", p])
    # timing
    if state.get("timing"):
        cmd.append(state["timing"][1])
    # misc
    for name, flag in state.get("misc", set()):
        if flag == "--spoof-mac":
            val = state.get("misc_values", {}).get("--spoof-mac", "")
            if val:
                cmd.extend([flag, val])
            else:
                cmd.append(flag)
        else:
            cmd.append(flag)
    # nse
    if state.get("nse"):
        scripts = ",".join(sorted(state.get("nse")))
        if scripts:
            cmd.append(f"--script={scripts}")
    # advanced flags (show only raw string to avoid parsing)
    if state.get("advanced_flags"):
        cmd.append(state.get("advanced_flags"))
    # decoy/source port preview
    if state.get("decoy"):
        cmd.extend(["-D", state.get("decoy")])
    if state.get("source_port"):
        cmd.extend(["--source-port", state.get("source_port")])
    # output preview
    if state.get("output"):
        flag = state["output"][1]
        name = state.get("output_name", "")
        if name:
            # show path inside session dir if known
            base = state.get("session_dir") or os.path.join(os.path.dirname(__file__), "sessions")
            cmd.extend([flag, os.path.join(base, name)])
        else:
            cmd.append(flag)
    # target (show placeholder if not set)
    tgt = state.get("target") or "<target>"
    cmd.append(tgt)
    # indicate pcap preview state
    if state.get("pcap_enabled"):
        pcap_name = state.get("pcap_file_name") or "<pcap-auto>"
        cmd.append(f"[pcap:{pcap_name}]")
    if state.get("trace_enabled"):
        cmd.append("[trace]")
    return cmd


def find_dumpcap_windows():
    """Try to locate dumpcap.exe on Windows. Return path or None."""
    # common installs
    candidates = []
    pf = os.environ.get('ProgramFiles')
    pfx86 = os.environ.get('ProgramFiles(x86)')
    if pf:
        candidates.append(os.path.join(pf, 'Wireshark', 'dumpcap.exe'))
    if pfx86:
        candidates.append(os.path.join(pfx86, 'Wireshark', 'dumpcap.exe'))
    # also search top-level Program Files dirs (limited) for dumpcap.exe
    for root in filter(None, [pf, pfx86]):
        try:
            for name in os.listdir(root):
                candidate = os.path.join(root, name, 'Wireshark', 'dumpcap.exe')
                if os.path.exists(candidate):
                    return candidate
        except Exception:
            continue
    # fallback: try well-known path under C:\
    well_known = [r"C:\Program Files\Wireshark\dumpcap.exe", r"C:\Program Files (x86)\Wireshark\dumpcap.exe"]
    for w in well_known:
        if os.path.exists(w):
            return w
    return None


def list_capture_interfaces():
    """Return a list of available capture interfaces by calling dumpcap -D or tcpdump -D if available."""
    outputs = []
    prog = None
    if which('dumpcap'):
        prog = which('dumpcap')
        args = [prog, '-D']
    elif which('tcpdump'):
        prog = which('tcpdump')
        args = [prog, '-D']
    elif os.name == 'nt':
        # try to find dumpcap in standard Wireshark locations
        dc = find_dumpcap_windows()
        if dc:
            prog = dc
            args = [prog, '-D']
    if not prog:
        return None, 'no_capture_program'
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=5)
        out = p.stdout.strip() or p.stderr.strip()
        lines = [l for l in (out.splitlines() if out else [])]
        return lines, None
    except Exception as e:
        return None, str(e)


def print_cmd_preview():
    """Print a one-line preview of the nmap command at the bottom of menus."""
    try:
        cmd = build_nmap_preview()
        # keep it concise
        preview = " ".join([str(x) for x in cmd]).strip()
        print()
        print(colored("Nmap preview:", Fore.MAGENTA) + " " + colored(preview, Fore.CYAN))
    except Exception:
        pass

def prompt_choice(prompt, valid=None, allow_empty=False):
    while True:
        val = input(colored(prompt, Fore.YELLOW)).strip()
        if allow_empty and val == "":
            return val
        if valid is None or val in valid:
            # immediate feedback of raw selection for user clarity
            try:
                if val != "":
                    print(colored(f"You selected: {val}", Fore.BLUE))
            except Exception:
                pass
            return val
        print(colored("Invalid selection, try again.", Fore.RED))

def show_group(title, options):
    clear_screen()
    print(colored(f"== {title} ==", Fore.GREEN))
    name_width = 30
    for k, tup in options.items():
        # support both (name,flag,desc) and (name,desc)
        if len(tup) == 3:
            name, flag, desc = tup
        else:
            name, desc = tup
            flag = ""
        wrapped = textwrap.fill(desc, width=60, subsequent_indent=' ' * (6 + name_width))
        left = colored(f" {k}) {name.ljust(name_width)}", Fore.CYAN)
        print(left + " - " + wrapped)
    # show live nmap command preview at bottom
    try:
        print_cmd_preview()
    except Exception:
        pass

def show_simple_group(title, options):
    clear_screen()
    print(colored(f"== {title} ==", Fore.GREEN))
    name_width = 30
    for k, (name, desc) in options.items():
        wrapped = textwrap.fill(desc, width=60, subsequent_indent=' ' * (6 + name_width))
        left = colored(f" {k}) {name.ljust(name_width)}", Fore.CYAN)
        print(left + " - " + wrapped)
    # show live nmap command preview at bottom
    try:
        print_cmd_preview()
    except Exception:
        pass


def save_session(cmd_list, result_note=""):
    """Save a session JSON with state, command, and metadata."""
    # prefer an already-created per-session dir when present
    try:
        base_sessions = os.path.join(os.path.dirname(__file__), "sessions")
    except Exception:
        base_sessions = os.path.join(os.getcwd(), "sessions")
    os.makedirs(base_sessions, exist_ok=True)
    session_dir = state.get("session_dir") or base_sessions
    os.makedirs(session_dir, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    fname = f"session_{ts}.json" if not state.get("session_dir") else "session.json"
    path = os.path.join(session_dir, fname)
    data = {
        "timestamp_utc": ts,
        "operator": state.get("operator", ""),
        "roe_acknowledged": bool(state.get("roe_acknowledged", False)),
        "target": state.get("target", ""),
        "scan_type": state.get("scan_type"),
        "nse": sorted(list(state.get("nse", []))) if state.get("nse") else [],
        "port_mode": state.get("port_mode"),
        "port_arg": state.get("port_arg"),
        "timing": state.get("timing"),
        "misc": list(state.get("misc", [])),
        "advanced_flags": state.get("advanced_flags", ""),
        "decoy": state.get("decoy"),
        "source_port": state.get("source_port"),
        "pcap_file": state.get("pcap_file"),
        "command": " ".join(cmd_list),
        "note": result_note,
        "summary": None,
        "artifacts": [],
    }
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(colored(f"Session saved to: {path}", Fore.GREEN))
    except Exception as e:
        print(colored(f"Failed to save session: {e}", Fore.RED))
    return path


def require_roe():
    """Prompt and record Rules of Engagement acknowledgement and operator name."""
    if state.get("roe_acknowledged"):
        return True
    print(colored("\nRules of Engagement (ROE) and Authorization", Fore.MAGENTA))
    print(colored("You must have explicit authorization to test targets. This will be logged.", Fore.YELLOW))
    op = input(colored("Operator name (first.last or handle): ", Fore.YELLOW)).strip()
    if not op:
        print(colored("Operator name required.", Fore.RED))
        return False
    ok = input(colored(CONFIRM_TEXT, Fore.YELLOW)).strip().lower()
    if ok != "yes":
        print(colored("ROE not acknowledged — aborting intrusive action.", Fore.RED))
        return False
    state["operator"] = op
    state["roe_acknowledged"] = True
    print(colored("ROE acknowledged and recorded.", Fore.GREEN))
    return True

def validate_target(t):
    t = t.strip()
    # try IP / CIDR
    try:
        if "/" in t:
            ipaddress.ip_network(t, strict=False)
            return True
        else:
            ipaddress.ip_address(t)
            return True
    except Exception:
        pass
    # basic hostname/fqdn validation
    if re.match(r"^[A-Za-z0-9][A-Za-z0-9\.-]{0,253}[A-Za-z0-9]$", t):
        return True
    return False

# Menus
def menu_scan_types():
    while True:
        show_group("Scan Types (select one)", SCAN_TYPES)
        print(" 0) Back")
        choice = prompt_choice("Select scan type number: ", valid=list(SCAN_TYPES.keys())+["0"])
        if choice == "0":
            return
        name, flag, desc = SCAN_TYPES[choice]
        # Only one scan type allowed; auto-correct by replacing
        state["scan_type"] = (name, flag)
        print(colored(f"Selected scan type: {name}", Fore.GREEN))

def menu_nse():
    while True:
        show_simple_group("NSE Script Categories", NSE_CATEGORIES)
        print(colored(" 0) Back", Fore.CYAN))
        choice = prompt_choice("Select NSE category number (comma separated allowed): ", allow_empty=True)
        if choice == "" or choice == "0":
            return
        parts = [p.strip() for p in choice.split(",") if p.strip() in NSE_CATEGORIES]
        for p in parts:
            cat = NSE_CATEGORIES[p][0]
            state["nse"].add(cat)
            print(colored(f"Added NSE category: {cat}", Fore.GREEN))

def menu_ports():
    while True:
        show_group("Port Options", PORT_OPTIONS)
        print(colored(" 0) Back", Fore.CYAN))
        choice = prompt_choice("Select port option: ", valid=list(PORT_OPTIONS.keys())+["0"])
        if choice == "0":
            return
        name, flag, desc = PORT_OPTIONS[choice]
        state["port_mode"] = name
        if flag == "-p":
            v = input(colored("Enter custom ports (e.g. 1-65535 or 22,80,443): ", Fore.YELLOW)).strip()
            state["port_arg"] = v
        elif flag.startswith("--top-ports"):
            state["port_arg"] = "1000"
        else:
            state["port_arg"] = ""
        print(colored(f"Port selection: {state['port_mode']} {state['port_arg']}", Fore.GREEN))
        return

def menu_timing():
    while True:
        show_group("Timing Templates", TIMING_OPTIONS)
        print(colored(" 0) Back", Fore.CYAN))
        choice = prompt_choice("Select timing: ", valid=list(TIMING_OPTIONS.keys())+["0"])
        if choice == "0":
            return
        name, flag, desc = TIMING_OPTIONS[choice]
        state["timing"] = (name, flag)
        print(colored(f"Selected timing: {name}", Fore.GREEN))
        return

def menu_output():
    while True:
        show_group("Output Options", OUTPUT_OPTIONS)
        print(colored(" 0) Back", Fore.CYAN))
        choice = prompt_choice("Select output option: ", valid=list(OUTPUT_OPTIONS.keys())+["0"])
        if choice == "0":
            return
        name, flag, desc = OUTPUT_OPTIONS[choice]
        base = input(colored("Enter base filename for output (no extension): ", Fore.YELLOW)).strip()
        if base == "":
            print(colored("Filename cannot be empty.", Fore.RED))
            continue
        state["output"] = (name, flag)
        state["output_name"] = base
        print(colored(f"Output: {name} -> {base}", Fore.GREEN))
        return

def menu_misc():
    while True:
        show_group("Misc Options", MISC_OPTIONS)
        print(colored(" 0) Back", Fore.CYAN))
        choice = prompt_choice("Select misc option number (comma separated allowed): ", allow_empty=True)
        if choice == "" or choice == "0":
            return
        parts = [p.strip() for p in choice.split(",")]
        for p in parts:
            if p not in MISC_OPTIONS:
                print(colored(f"Ignoring invalid misc option {p}", Fore.RED))
                continue
            name, flag, desc = MISC_OPTIONS[p]
            state["misc"].add((name, flag))
            if flag == "--spoof-mac":
                val = input(colored("Enter MAC value or 'random': ", Fore.YELLOW)).strip()
                state["misc_values"]["--spoof-mac"] = val
        print(colored(f"Selected misc options: {', '.join([n for n,_ in state['misc']])}", Fore.GREEN))


def menu_pen_testing():
    """Penetration testing helpers: quick vuln probes and exploit selection.
    This menu helps add intrusive NSE categories with explicit confirmation.
    """
    while True:
        print(colored("\n== Penetration Testing ==" , Fore.GREEN))
        print(colored(" 1) Quick vulnerability scan (adds 'vuln')", Fore.CYAN))
        print(colored(" 2) Exploit scan (adds 'exploit' - very intrusive)", Fore.CYAN))
        print(colored(" 3) Credential/Brute-force guidance (external tools)", Fore.CYAN))
        print(colored(" 4) Session & Advanced options", Fore.CYAN))
        print(colored(" 0) Back", Fore.CYAN))
        choice = prompt_choice("Select pen-testing option: ", valid=["0","1","2","3","4"]) 
        if choice == "0":
            return
        elif choice == "1":
            state["nse"].add("vuln")
            print(colored("Added NSE category: vuln (vulnerability checks)", Fore.GREEN))
        elif choice == "2":
            print(colored("Exploit scans are highly intrusive and may cause damage.", Fore.RED))
            if not require_roe():
                continue
            state["nse"].add("exploit")
            print(colored("Added NSE category: exploit", Fore.GREEN))
        elif choice == "3":
            print(colored("This option provides guidance only. Use dedicated tools (hydra, medusa, etc.).", Fore.YELLOW))
            print(colored("The script will not perform brute-force itself to avoid unsafe behavior.", Fore.YELLOW))
        elif choice == "4":
            menu_session_advanced()
        elif choice == "5":
            menu_red_team()
        # continue loop to allow multiple selections

def set_target():
    while True:
        t = input(colored("Enter target (IP, CIDR, or hostname): ", Fore.YELLOW)).strip()
        if validate_target(t):
            state["target"] = t
            print(colored(f"Target set to: {t}", Fore.GREEN))
            return
        else:
            print(colored("Invalid target format. Try again.", Fore.RED))


def menu_session_advanced():
    """Session logging, advanced flags, decoy/source-port and pcap toggles."""
    while True:
        clear_screen()
        print(colored("== Session & Advanced Options ==", Fore.GREEN))
        left = colored(" 1) Set operator name", Fore.CYAN)
        print(left + " - Set operator identity for session logs")
        left = colored(" 2) Toggle ROE acknowledgement", Fore.CYAN)
        print(left + " - Must be acknowledged for intrusive actions")
        left = colored(" 3) Toggle session logging", Fore.CYAN)
        print(left + " - Save session JSON for audit")
        left = colored(" 4) Set advanced nmap flags", Fore.CYAN)
        print(left + " - Paste extra flags (gated by ROE)")
        left = colored(" 5) Set decoy (-D)", Fore.CYAN)
        print(left + " - Comma-separated decoy addresses or 'random'")
        left = colored(" 6) Set source port (--source-port)", Fore.CYAN)
        print(left + " - Numeric port")
        left = colored(" 7) Toggle pcap capture", Fore.CYAN)
        print(left + " - Capture traffic during scan if available")
        left = colored(" 8) Set PCAP filename", Fore.CYAN)
        print(left + " - Base filename (no path, e.g. capture1 or capture1.pcap)")
        left = colored(" 9) Set PCAP interface", Fore.CYAN)
        print(left + " - e.g. eth0 or 1 (leave empty to auto-select)")
        left = colored("10) Set PCAP capture filter", Fore.CYAN)
        print(left + " - BPF filter (e.g. 'port 80')")
        left = colored("11) Toggle packet trace (--packet-trace)", Fore.CYAN)
        print(left + " - Enable nmap packet trace and capture to pcap")
        print(colored(" 0) Back", Fore.CYAN))
        choice = prompt_choice("Select session/advanced option: ", valid=[str(i) for i in range(0,13)])
        if choice == "0":
            return
        elif choice == "1":
            op = input(colored("Operator name: ", Fore.YELLOW)).strip()
            if op:
                state["operator"] = op
                print(colored("Operator recorded.", Fore.GREEN))
        elif choice == "2":
            if require_roe():
                print(colored("ROE is acknowledged and logged.", Fore.GREEN))
        elif choice == "3":
            # toggling session logging is implicit - presence of sessions dir indicates saving
            val = input(colored("Enable session logging? (yes/no): ", Fore.YELLOW)).strip().lower()
            if val == "yes":
                print(colored("Session logging enabled. Sessions will be saved after run.", Fore.GREEN))
            else:
                print(colored("Session logging remains enabled by default (no-op).", Fore.YELLOW))
        elif choice == "4":
            if not require_roe():
                continue
            flags = input(colored("Enter extra nmap flags (e.g. --data-length 20 -S 1.2.3.4): ", Fore.YELLOW)).strip()
            state["advanced_flags"] = flags
            print(colored("Advanced flags set (will be appended at execution).", Fore.GREEN))
        elif choice == "5":
            val = input(colored("Enter decoy list (comma separated) or 'random': ", Fore.YELLOW)).strip()
            state["decoy"] = val
            print(colored("Decoy value recorded (logged).", Fore.GREEN))
        elif choice == "6":
            val = input(colored("Enter source port number to use (--source-port): ", Fore.YELLOW)).strip()
            state["source_port"] = val
            print(colored("Source port recorded (logged).", Fore.GREEN))
        elif choice == "7":
            if state.get("pcap_enabled"):
                state["pcap_enabled"] = False
                print(colored("PCAP capture disabled.", Fore.GREEN))
            else:
                state["pcap_enabled"] = True
                print(colored("PCAP capture enabled (will attempt capture if tcpdump/dumpcap present).", Fore.GREEN))
        elif choice == "8":
            fname = input(colored("Enter PCAP base filename (no path, .pcap optional): ", Fore.YELLOW)).strip()
            if fname:
                state["pcap_file_name"] = fname
                print(colored(f"PCAP filename set to: {fname}", Fore.GREEN))
            else:
                print(colored("PCAP filename left empty; default will be used.", Fore.YELLOW))
        elif choice == "9":
            iface = input(colored("Enter PCAP interface (name or number, empty to auto): ", Fore.YELLOW)).strip()
            state["pcap_iface"] = iface
            print(colored(f"PCAP interface set to: {iface or '<auto>'}", Fore.GREEN))
        elif choice == "10":
            pf = input(colored("Enter PCAP capture filter (BPF), or leave empty: ", Fore.YELLOW)).strip()
            state["pcap_filter"] = pf
            print(colored(f"PCAP filter set to: {pf or '<none>'}", Fore.GREEN))
        elif choice == "11":
            # toggle packet trace feature
            if state.get("trace_enabled"):
                state["trace_enabled"] = False
                print(colored("Packet trace disabled.", Fore.GREEN))
            else:
                state["trace_enabled"] = True
                # when trace is enabled, also enable pcap capture so user gets a pcap
                state["pcap_enabled"] = True
                print(colored("Packet trace enabled: nmap --packet-trace will be used and PCAP capture started.", Fore.GREEN))
        elif choice == "12":
            # list capture interfaces
            print(colored("Detecting available capture interfaces...", Fore.YELLOW))
            lines, err = list_capture_interfaces()
            if err:
                print(colored(f"Failed to list interfaces: {err}", Fore.RED))
            else:
                if not lines:
                    print(colored("No interfaces reported.", Fore.YELLOW))
                else:
                    print(colored("Available capture interfaces:", Fore.CYAN))
                    for l in lines:
                        print(colored(f"  {l}", Fore.GREEN))


def menu_red_team():
    """Red Team specific presets and quick toggles.
    This menu reuses existing flags but groups them in presets useful for red-team workflows.
    Actions that are intrusive require ROE acknowledgement and are logged.
    """
    while True:
        clear_screen()
        print(colored("== Red Team Presets & Quick Toggles ==", Fore.GREEN))
        left = colored(" 1) Recon Preset (fast)", Fore.CYAN)
        print(left + " - Top ports, normal timing, service detection")
        left = colored(" 2) Stealth Recon Preset", Fore.CYAN)
        print(left + " - SYN scan, sneaky timing, limited ports (requires ROE for intrusive flags)")
        left = colored(" 3) Enumeration Preset", Fore.CYAN)
        print(left + " - Service/version + default NSE discovery scripts")
        left = colored(" 4) Toggle packet fragmentation (-f)", Fore.CYAN)
        print(left + " - Fragment packets (use responsibly)")
        left = colored(" 5) Toggle disable host discovery (-Pn)", Fore.CYAN)
        print(left + " - Treat hosts as up; useful when ICMP is filtered")
        left = colored(" 6) Toggle MAC spoofing", Fore.CYAN)
        print(left + " - Will prompt for value when enabling")
        left = colored(" 0) Back", Fore.CYAN)
        print(left)
        choice = prompt_choice("Select red-team preset/toggle: ", valid=[str(i) for i in range(0,7)])
        if choice == "0":
            return
        elif choice == "1":
            # Recon preset: top ports, normal timing, sV
            state["port_mode"] = "Top 1000"
            state["port_arg"] = "1000"
            state["timing"] = (TIMING_OPTIONS["4"][0], TIMING_OPTIONS["4"][1])
            state["scan_type"] = (SCAN_TYPES["1"][0], SCAN_TYPES["1"][1])
            state["misc"].add(("Service/version detection", "-sV"))
            print(colored("Recon preset applied.", Fore.GREEN))
        elif choice == "2":
            # Stealth preset: SYN + sneaky timing
            if not require_roe():
                continue
            state["scan_type"] = (SCAN_TYPES["1"][0], SCAN_TYPES["1"][1])
            state["timing"] = (TIMING_OPTIONS["2"][0], TIMING_OPTIONS["2"][1])
            state["port_mode"] = "Top 1000"
            state["port_arg"] = "1000"
            print(colored("Stealth recon preset applied (logged).", Fore.GREEN))
        elif choice == "3":
            state["misc"].add(("Service/version detection", "-sV"))
            state["nse"].add("discovery")
            print(colored("Enumeration preset applied.", Fore.GREEN))
        elif choice == "4":
            # Toggle fragmentation
            if ("Fragment packets", "-f") in state["misc"]:
                state["misc"].discard(("Fragment packets", "-f"))
                print(colored("Packet fragmentation disabled.", Fore.GREEN))
            else:
                state["misc"].add(("Fragment packets", "-f"))
                print(colored("Packet fragmentation enabled (logged).", Fore.GREEN))
        elif choice == "5":
            # Toggle -Pn
            if ("Disable host discovery (-Pn)", "-Pn") in state["misc"]:
                state["misc"].discard(("Disable host discovery (-Pn)", "-Pn"))
                print(colored("Host discovery enabled.", Fore.GREEN))
            else:
                state["misc"].add(("Disable host discovery (-Pn)", "-Pn"))
                print(colored("Host discovery disabled (-Pn) enabled.", Fore.GREEN))
        elif choice == "6":
            val = input(colored("Enter MAC value to spoof or 'random': ", Fore.YELLOW)).strip()
            if val:
                state["misc_values"]["--spoof-mac"] = val
                state["misc"].add(("Spoof MAC", "--spoof-mac"))
                print(colored("MAC spoofing set and logged.", Fore.GREEN))


def parse_nmap_output(output_text):
    """Parse basic nmap stdout into a structured summary.
    This is a lightweight parser intended to extract open ports, services, and OS hints.
    """
    lines = output_text.splitlines()
    summary = {
        "hosts": [],
        "ports": [],
        "os": None,
        "notes": [],
    }
    host = None
    in_port_section = False
    for i, line in enumerate(lines):
        line = line.rstrip()
        if line.startswith("Nmap scan report for"):
            host = line.split("Nmap scan report for",1)[1].strip()
            summary["hosts"].append(host)
            in_port_section = False
            continue
        if re.match(r"^PORT\s+STATE\s+SERVICE", line):
            in_port_section = True
            continue
        if in_port_section:
            if line.strip() == "":
                in_port_section = False
                continue
            # parse lines like: 22/tcp open  ssh    OpenSSH 7.6p1 Ubuntu
            m = re.match(r"^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)(\s+(.+))?", line)
            if m:
                port = m.group(1)
                proto = m.group(2)
                state_ = m.group(3)
                service = m.group(4)
                rest = (m.group(6) or "").strip()
                summary["ports"].append({"port": port, "proto": proto, "state": state_, "service": service, "info": rest})
            else:
                # fallback: try to split on whitespace
                parts = line.split()
                if len(parts) >= 3:
                    p = parts[0]
                    s = parts[1]
                    svc = parts[2]
                    rest = " ".join(parts[3:]) if len(parts) > 3 else ""
                    summary["ports"].append({"port": p, "proto": "", "state": s, "service": svc, "info": rest})
        # OS hints
        if line.lower().startswith("os details:") or line.lower().startswith("os: "):
            summary["os"] = line.split(":",1)[1].strip()
        # look for explicit vulnerability markers
        if "vulnerable" in line.lower() or "vuln" in line.lower():
            summary["notes"].append(line.strip())
    return summary


def print_summary(summary):
    if not summary:
        print(colored("No summary available.", Fore.YELLOW))
        return
    hosts = summary.get("hosts", [])
    ports = summary.get("ports", [])
    osinfo = summary.get("os")
    notes = summary.get("notes", [])
    if hosts:
        print(colored(f"Hosts found: {', '.join(hosts)}", Fore.CYAN))
    if osinfo:
        print(colored(f"OS: {osinfo}", Fore.CYAN))
    if ports:
        print(colored("Open ports:", Fore.GREEN))
        for p in ports:
            line = f" {p.get('port')}/{p.get('proto')} {p.get('state')} {p.get('service')}"
            if p.get('info'):
                line += f" -- {p.get('info')}"
            print(colored(line, Fore.YELLOW))
    else:
        print(colored("No open ports found or parser couldn't detect ports.", Fore.YELLOW))
    if notes:
        print(colored("Notes:", Fore.MAGENTA))
        for n in notes:
            print(colored(f" - {n}", Fore.RED))


def format_summary_text(summary):
    """Return a plain-text human readable summary for saving to file."""
    if not summary:
        return "No summary available.\n"
    out = []
    hosts = summary.get("hosts", [])
    ports = summary.get("ports", [])
    osinfo = summary.get("os")
    notes = summary.get("notes", [])
    if hosts:
        out.append(f"Hosts found: {', '.join(hosts)}")
    if osinfo:
        out.append(f"OS: {osinfo}")
    if ports:
        out.append("Open ports:")
        for p in ports:
            line = f" {p.get('port')}/{p.get('proto')} {p.get('state')} {p.get('service')}"
            if p.get('info'):
                line += f" -- {p.get('info')}"
            out.append(line)
    else:
        out.append("No open ports found or parser couldn't detect ports.")
    if notes:
        out.append("Notes:")
        for n in notes:
            out.append(f" - {n}")
    out.append("")
    return "\n".join(out)

def review_and_run():
    if not state["target"]:
        print(colored("No target specified. Please set a target first.", Fore.RED))
        return
    # create a per-session directory for artifacts
    try:
        base_sessions = os.path.join(os.path.dirname(__file__), "sessions")
    except Exception:
        base_sessions = os.path.join(os.getcwd(), "sessions")
    os.makedirs(base_sessions, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    session_dir = os.path.join(base_sessions, f"session_{ts}")
    os.makedirs(session_dir, exist_ok=True)
    state["session_dir"] = session_dir

    # Build command with compatibility corrections
    cmd = ["nmap"]
    # Scan type
    if state["scan_type"]:
        cmd.append(state["scan_type"][1])
    # Ports
    if state["port_mode"] == "Top 1000":
        cmd.extend(["--top-ports", state["port_arg"] or "1000"])
    elif state["port_mode"] == "Custom range":
        cmd.extend(["-p", state["port_arg"] or ""])
    # Timing
    if state["timing"]:
        cmd.append(state["timing"][1])
    # Misc
    for name, flag in state["misc"]:
        if flag == "--spoof-mac":
            val = state["misc_values"].get("--spoof-mac", "")
            if val:
                cmd.extend([flag, val])
        else:
            cmd.append(flag)
    # NSE
    if state["nse"]:
        # If user selected 'all' then ensure they confirm intrusive categories
        if "all" in state["nse"] or "exploit" in state["nse"] or "vuln" in state["nse"]:
            print(colored("\nYou selected high-impact NSE categories (vuln/exploit/all).", Fore.RED))
            confirm = input(colored("These can be intrusive. Do you have authorization? (yes/no): ", Fore.YELLOW)).strip().lower()
            if confirm != "yes":
                print(colored("NSE selection cleared for safety.", Fore.RED))
                state["nse"].discard("all")
                state["nse"].discard("exploit")
                state["nse"].discard("vuln")
        # Build script argument like --script=vuln,discovery
        if state["nse"]:
            scripts = ",".join(sorted(state["nse"]))
            cmd.append(f"--script={scripts}")
    # Version/service and OS detection typically requested via misc
    # Output
    if state["output"]:
        flag = state["output"][1]
        fname = state["output_name"]
        # ensure output files are generated inside the session dir
        fullpath = os.path.join(state.get("session_dir", base_sessions), fname)
        cmd.extend([flag, fullpath])
    # Target
    cmd.append(state["target"])

    # Auto-correction examples
    # If -sU (UDP) and -sT/-sS both present, prefer UDP only (remove TCP scan)
    if state["scan_type"] and state["scan_type"][1] == "-sU" and any(state["scan_type"][1] == v for k,(n,v,d) in SCAN_TYPES.items() if v in ("-sS","-sT")):
        # This logical check may be redundant given single selection enforced, kept for demonstration
        pass

    print(colored("\nFinal nmap command to run:", Fore.GREEN))
    print(colored(" ".join(cmd), Fore.CYAN))
    # Confirm legal/ethical notice
    ok = input(colored("\n" + CONFIRM_TEXT, Fore.YELLOW)).strip().lower()
    if ok != "yes":
        print(colored("Scan cancelled.", Fore.RED))
        return
    # Append advanced flags, decoy, source port
    if state.get("advanced_flags"):
        try:
            extra = shlex.split(state["advanced_flags"])
            cmd.extend(extra)
        except Exception:
            cmd.append(state.get("advanced_flags"))
    if state.get("decoy"):
        # nmap uses -D list
        cmd.extend(["-D", state.get("decoy")])
    if state.get("source_port"):
        cmd.extend(["--source-port", state.get("source_port")])

    # Run nmap (with optional pcap capture)
    pcap_proc = None
    errors = []
    pcap_prog = None
    if state.get("pcap_enabled"):
        # attempt to start a pcap tool if available: prefer tcpdump, then dumpcap, else try Windows common path
        if which("tcpdump"):
            pcap_prog = which("tcpdump")
        elif which("dumpcap"):
            pcap_prog = which("dumpcap")
        elif os.name == 'nt':
            # try common Wireshark install locations
            candidates = [
                r"C:\Program Files\Wireshark\dumpcap.exe",
                r"C:\Program Files (x86)\Wireshark\dumpcap.exe",
            ]
            for c in candidates:
                if os.path.exists(c):
                    pcap_prog = c
                    break
        if not pcap_prog:
            print(colored("No pcap capture program (tcpdump/dumpcap) found. PCAP will not be captured.", Fore.YELLOW))
            errors.append("pcap_program_not_found")
        else:
            if state.get("dry_run"):
                print(colored("Dry-run: PCAP capture skipped.", Fore.YELLOW))
            else:
                # save pcap into the per-run session_dir (created above)
                try:
                    os.makedirs(session_dir, exist_ok=True)
                except Exception:
                    pass
                # use user-specified filename if provided, otherwise default to timestamped name
                fname = state.get("pcap_file_name") or ""
                if fname:
                    if not fname.lower().endswith('.pcap'):
                        fname = fname + '.pcap'
                    pcap_file = os.path.join(session_dir, fname)
                else:
                    pcap_file = os.path.join(session_dir, f"capture_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.pcap")
                try:
                    iface = state.get("pcap_iface") or None
                    pf = state.get("pcap_filter") or None
                    base_prog = os.path.basename(str(pcap_prog)).lower()
                    if 'tcpdump' in base_prog:
                        pcap_cmd = [pcap_prog]
                        if iface:
                            pcap_cmd.extend(["-i", iface])
                        pcap_cmd.extend(["-w", pcap_file])
                        if pf:
                            pcap_cmd.extend(shlex.split(pf))
                        pcap_proc = subprocess.Popen(pcap_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    else:
                        # dumpcap or dumpcap.exe
                        pcap_cmd = [pcap_prog]
                        if iface:
                            pcap_cmd.extend(["-i", iface])
                        pcap_cmd.extend(["-w", pcap_file])
                        if pf:
                            pcap_cmd.extend(["-f", pf])
                        pcap_proc = subprocess.Popen(pcap_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    state["pcap_file"] = pcap_file
                    print(colored(f"Started pcap capture: {pcap_file}", Fore.GREEN))
                except Exception as e:
                    err = f"Failed to start pcap capture: {e}"
                    print(colored(err, Fore.RED))
                    errors.append(err)

    result = None
    session_path = None
    try:
        print(colored("\nRunning nmap... (press Ctrl-C to cancel)", Fore.GREEN))
        # if trace enabled, add nmap packet trace flag
        if state.get("trace_enabled"):
            cmd.append("--packet-trace")
        if state.get("dry_run"):
            print(colored("Dry-run: Skipping nmap execution.", Fore.YELLOW))
            result = None
        else:
            result = subprocess.run(cmd, capture_output=True, text=True)
    except KeyboardInterrupt:
        print(colored("\nScan interrupted by user.", Fore.RED))
    except Exception as e:
        tb = traceback.format_exc()
        err = f"Failed to run nmap: {e}\n{tb}"
        print(colored(err, Fore.RED))
        errors.append(err)
        # ensure pcap proc is stopped
        if pcap_proc:
            try:
                pcap_proc.terminate()
                pcap_proc.wait(timeout=5)
            except Exception:
                pass
        # save session including error details
        try:
            save_session(cmd, result_note=err)
        except Exception:
            pass
        return
    finally:
        if pcap_proc:
            try:
                pcap_proc.terminate()
                pcap_proc.wait(timeout=5)
                pcap_path = state.get('pcap_file')
                print(colored(f"PCAP capture saved to: {pcap_path}", Fore.GREEN))
                print(colored(f"\n[PCAP file location]", Fore.YELLOW))
                print(colored(f"  {pcap_path}", Fore.CYAN))
            except Exception:
                pass
    # save session and produce summary; write artifacts into session dir
    # save raw stdout/stderr
    session_path = save_session(cmd)
    summary = None
    if result is not None:
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        # write raw outputs
        try:
            with open(os.path.join(session_dir, "nmap_stdout.txt"), "w", encoding="utf-8") as f:
                f.write(stdout)
            with open(os.path.join(session_dir, "nmap_stderr.txt"), "w", encoding="utf-8") as f:
                f.write(stderr)
            # record artifacts in session JSON
            try:
                with open(session_path, "r+", encoding="utf-8") as f:
                    data = json.load(f)
                    data.setdefault("artifacts", [])
                    data["artifacts"].extend(["nmap_stdout.txt", "nmap_stderr.txt"])
                    f.seek(0)
                    json.dump(data, f, indent=2)
                    f.truncate()
            except Exception:
                pass
        except Exception:
            pass

        summary = parse_nmap_output(stdout)
        # print a neat human-readable summary
        print(colored("\n=== Scan Summary ===", Fore.MAGENTA))
        print_summary(summary)

        # save human-readable summary and parsed JSON summary into session dir
        try:
            txt = format_summary_text(summary)
            with open(os.path.join(session_dir, "summary.txt"), "w", encoding="utf-8") as f:
                f.write(txt)
            with open(os.path.join(session_dir, "summary.json"), "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2)
            # update session JSON to reference artifacts
            try:
                with open(session_path, "r+", encoding="utf-8") as f:
                    data = json.load(f)
                    data["summary"] = summary
                    data.setdefault("artifacts", [])
                    data["artifacts"].extend(["summary.txt", "summary.json"])
                    f.seek(0)
                    json.dump(data, f, indent=2)
                    f.truncate()
            except Exception:
                pass
        except Exception:
            pass
    else:
        # dry-run case: save only the built command to a file for review
        try:
            with open(os.path.join(session_dir, "command.txt"), "w", encoding="utf-8") as f:
                f.write(" ".join(cmd))
            try:
                with open(session_path, "r+", encoding="utf-8") as f:
                    data = json.load(f)
                    data.setdefault("artifacts", [])
                    data["artifacts"].append("command.txt")
                    f.seek(0)
                    json.dump(data, f, indent=2)
                    f.truncate()
            except Exception:
                pass
        except Exception:
            pass

def main_menu():
    while True:
        clear_screen()
        print(colored("=== Nmap Interactive Wizard ===", Fore.MAGENTA))
        print(colored(" 1) Scan Types", Fore.CYAN))
        print(colored(" 2) NSE Script Categories", Fore.CYAN))
        print(colored(" 3) Port Options", Fore.CYAN))
        print(colored(" 4) Timing Templates", Fore.CYAN))
        print(colored(" 5) Penetration Testing", Fore.CYAN))
        print(colored(" 6) Output Options", Fore.CYAN))
        print(colored(" 7) Misc Options", Fore.CYAN))
        print(colored(" 8) Set Target", Fore.CYAN))
        print(colored(" 9) Review & Run", Fore.CYAN))
        print(colored(" 0) Exit", Fore.CYAN))
        # show live preview of the command before asking for selection
        try:
            print_cmd_preview()
        except Exception:
            pass
        choice = prompt_choice("Select menu number: ", valid=[str(i) for i in range(0,10)])
        if choice == "0":
            print(colored("Exiting.", Fore.MAGENTA))
            return
        elif choice == "1":
            menu_scan_types()
        elif choice == "2":
            menu_nse()
        elif choice == "3":
            menu_ports()
        elif choice == "4":
            menu_timing()
        elif choice == "5":
            menu_pen_testing()
        elif choice == "6":
            menu_output()
        elif choice == "7":
            menu_misc()
        elif choice == "8":
            set_target()
        elif choice == "9":
            review_and_run()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Interactive Nmap runner with session logging and advanced options")
    parser.add_argument("--dry-run", action="store_true", help="Build and show nmap command but do not execute")
    parser.add_argument("--target", help="Target IP/CIDR/hostname")
    parser.add_argument("--scan-type", help="Scan type number from menu (e.g. 1 for SYN)")
    parser.add_argument("--nse", help="Comma separated NSE categories (names or numbers)")
    parser.add_argument("--ports", help="Port option number or custom port list")
    parser.add_argument("--timing", help="Timing option number")
    parser.add_argument("--misc", help="Comma separated misc option numbers")
    parser.add_argument("--advanced", help="Extra nmap flags (quoted)")
    parser.add_argument("--decoy", help="Decoy list (comma separated) or 'random'")
    parser.add_argument("--source-port", help="Source port number to use")
    parser.add_argument("--pcap", action="store_true", help="Enable pcap capture during scan if available")
    parser.add_argument("--trace", action="store_true", help="Enable packet trace (--packet-trace) and capture to pcap")
    parser.add_argument("--pcap-file", help="Base filename for pcap output (no path, .pcap optional)")
    parser.add_argument("--pcap-interface", help="Capture interface to use (name or number)")
    parser.add_argument("--operator", help="Operator name for session logs")
    parser.add_argument("--confirm", action="store_true", help="Automatically confirm ROE (use with caution)")
    args = parser.parse_args()

    # If any CLI args (other than none) are present, run non-interactive
    if len(sys.argv) > 1:
        # map args to state
        # respect dry-run flag for later logic
        state["dry_run"] = bool(args.dry_run)
        if args.operator:
            state["operator"] = args.operator
        if args.confirm and not state.get("roe_acknowledged"):
            state["roe_acknowledged"] = True
        if args.target:
            state["target"] = args.target
        if args.scan_type and args.scan_type in SCAN_TYPES:
            name, flag, _ = SCAN_TYPES[args.scan_type]
            state["scan_type"] = (name, flag)
        if args.nse:
            parts = [p.strip() for p in args.nse.split(",")]
            for p in parts:
                if p in NSE_CATEGORIES:
                    state["nse"].add(NSE_CATEGORIES[p][0])
                else:
                    state["nse"].add(p)
        if args.ports:
            # if numeric option
            if args.ports in PORT_OPTIONS:
                state["port_mode"] = PORT_OPTIONS[args.ports][0]
                state["port_arg"] = PORT_OPTIONS[args.ports][1] if PORT_OPTIONS[args.ports][1] == "-p" else "1000"
            else:
                state["port_mode"] = "Custom range"
                state["port_arg"] = args.ports
        if args.timing and args.timing in TIMING_OPTIONS:
            state["timing"] = (TIMING_OPTIONS[args.timing][0], TIMING_OPTIONS[args.timing][1])
        if args.misc:
            parts = [p.strip() for p in args.misc.split(",")]
            for p in parts:
                if p in MISC_OPTIONS:
                    name, flag, _ = MISC_OPTIONS[p]
                    state["misc"].add((name, flag))
        if args.advanced:
            state["advanced_flags"] = args.advanced
        if args.decoy:
            state["decoy"] = args.decoy
        if args.source_port:
            state["source_port"] = args.source_port
        if args.pcap:
            state["pcap_enabled"] = True
        if args.trace:
            state["trace_enabled"] = True
            state["pcap_enabled"] = True
        if args.pcap_file:
            state["pcap_file_name"] = args.pcap_file
            state["pcap_enabled"] = True
        if args.pcap_interface:
            state["pcap_iface"] = args.pcap_interface

        # If any intrusive selections present and ROE not acknowledged, require confirmation
        if ("exploit" in state.get("nse", set()) or "vuln" in state.get("nse", set()) or state.get("advanced_flags")) and not state.get("roe_acknowledged"):
            if args.confirm:
                state["roe_acknowledged"] = True
            else:
                print(colored("Intrusive options selected but ROE not acknowledged. Use --confirm to auto-ack or run interactively.", Fore.RED))
                sys.exit(1)

        # Call review_and_run but handle dry-run
        # Build command without executing if dry-run
        review_and_run()
        if args.dry_run:
            print(colored("Dry-run requested. Command was not executed.", Fore.YELLOW))
            # session already saved by review_and_run
            sys.exit(0)
        sys.exit(0)
    else:
        try:
            main_menu()
        except KeyboardInterrupt:
            print("\nExiting.")