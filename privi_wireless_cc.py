#!/usr/bin/env python3
"""
🛰️ PRIVI-WIRELESS COMMAND CENTER (PWCC)
Centralized RF Intelligence & Audit Platform
Developed by Prince Ubebe | PriViSecurity
"""

from scapy.all import *
import threading
import time
import os
import sys
from rich.console import Console
from rich.table import Table as RichTable
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import IntPrompt
from fpdf import FPDF

# --- CONFIGURATION ---
INTERFACE = "wlan0mon"
ANALYST_NAME = "Prince Ubebe"
BRAND = "PriViSecurity"
MY_LAB_SSID = "PriVi_Lab_WiFi" 

console = Console()
networks = {} # {BSSID: [SSID, Ch, Sig, MFP]}
log_messages = []
stop_threads = False
captured_handshakes = []

class PDFReporter(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 16)
        self.cell(0, 10, f'🛡️ {BRAND} Wireless Audit Report', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}} - Audit Date: {time.strftime("%Y-%m-%d")}', 0, 0, 'C')

    def generate_report(self, scan_data):
        self.alias_nb_pages()
        self.add_page()
        self.set_font('Helvetica', 'B', 14)
        self.cell(0, 10, '1. Executive Summary', 0, 1)
        self.set_font('Helvetica', '', 11)
        self.multi_cell(0, 7, f"This document confirms the wireless audit results conducted by {ANALYST_NAME}. The session focused on spectral surveillance and vulnerability assessment of 802.11 management frames.")
        self.ln(5)
        
        self.set_font('Helvetica', 'B', 14)
        self.cell(0, 10, '2. Spectral Analysis Data', 0, 1)
        self.ln(2)

        # Table Header
        self.set_font('Helvetica', 'B', 10)
        self.set_fill_color(30, 30, 30)
        self.set_text_color(255, 255, 255)
        self.cell(45, 10, 'BSSID', 1, 0, 'C', 1)
        self.cell(70, 10, 'SSID', 1, 0, 'C', 1)
        self.cell(15, 10, 'CH', 1, 0, 'C', 1)
        self.cell(20, 10, 'Signal', 1, 0, 'C', 1)
        self.cell(40, 10, 'Security (MFP)', 1, 1, 'C', 1)

        # Table Body
        self.set_font('Helvetica', '', 9)
        self.set_text_color(0, 0, 0)
        for bssid, info in scan_data.items():
            ssid = info[0].replace("[bold red]", "").replace("[/bold red]", "")
            mfp = info[3].replace("[bold green]", "").replace("[/bold green]", "")
            self.cell(45, 10, bssid, 1)
            self.cell(70, 10, ssid, 1)
            self.cell(15, 10, str(info[1]), 1, 0, 'C')
            self.cell(20, 10, str(info[2]), 1, 0, 'C')
            self.cell(40, 10, mfp, 1, 1, 'C')

        self.ln(20)
        self.set_font('Times', 'BI', 15)
        self.cell(0, 10, f'~ Signed: {ANALYST_NAME} ~', 0, 1, 'R')
        self.set_font('Helvetica', 'I', 10)
        self.cell(0, 5, f'Lead Cybersecurity Analyst | {BRAND}', 0, 1, 'R')
        
        filename = f"PWCC_Audit_{time.strftime('%Y%m%d')}.pdf"
        self.output(filename)
        return filename

def update_logs(msg):
    log_messages.append(f"[bold green]»[/bold green] {time.strftime('%H:%M:%S')} | {msg}")
    if len(log_messages) > 10: log_messages.pop(0)

def channel_hopper():
    while not stop_threads:
        for ch in range(1, 14):
            os.system(f"iwconfig {INTERFACE} channel {ch}")
            time.sleep(0.5)

def packet_callback(pkt):
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt[Dot11Elt].info else "Hidden"
        
        # Evil Twin Detection
        if ssid == MY_LAB_SSID and bssid != "AA:BB:CC:DD:EE:FF": # Replace with your real MAC
            update_logs(f"[bold red]ALERT: EVIL TWIN DETECTED ({bssid})[/bold red]")
            ssid = f"[bold red]{ssid}[/bold red]"

        # Check for 802.11w (MFP)
        mfp = "Disabled"
        if pkt.haslayer(Dot11EltRSN):
            cap = pkt[Dot11EltRSN].cap
            if cap & 0x40 or cap & 0x80: mfp = "[bold green]Protected[/bold green]"

        networks[bssid] = [ssid, pkt[Dot11Beacon].network_stats().get("channel"), pkt.dBm_AntSignal, mfp]

    if pkt.haslayer(EAPOL):
        update_logs(f"[bold magenta]INTERCEPT:[/bold magenta] Handshake caught from {pkt[Dot11].addr3}")
        captured_handshakes.append(pkt)

def main():
    if os.getuid() != 0:
        console.print("[bold red]ERROR: PWCC requires root privileges.[/bold red]")
        sys.exit()

    os.system('clear')
    console.print(Panel.fit("[bold green]🛰️ PRIVI-WIRELESS COMMAND CENTER v3.0[/bold green]", border_style="green"))
    
    print("\n[1] SURVEILLANCE (Passive Recon)\n[2] INTERDICTION (Targeted Deauth)\n[3] BROADCAST SHUTDOWN (Massive Deauth)\n[4] DATA EXTRACTION (Handshake Hunt)")
    protocol = IntPrompt.ask("\nSelect Operational Protocol", choices=[1, 2, 3, 4])

    threading.Thread(target=channel_hopper, daemon=True).start()
    
    layout = Layout()
    layout.split_column(Layout(name="top", size=3), Layout(name="mid", size=15), Layout(name="bot", size=12))
    layout["top"].update(Panel(f"ANALYST: {ANALYST_NAME} | INTERFACE: {INTERFACE}", style="bold green"))

    update_logs(f"Protocol {protocol} Active. Initializing RF Engine...")

    try:
        with Live(layout, refresh_per_second=2):
            sniff_thread = threading.Thread(target=lambda: sniff(iface=INTERFACE, prn=packet_callback, store=0))
            sniff_thread.start()
            while True:
                table = RichTable(title="RF Spectrum Analysis", expand=True)
                table.add_column("BSSID", style="yellow")
                table.add_column("SSID", style="white")
                table.add_column("CH", style="green")
                table.add_column("SIG", style="magenta")
                table.add_column("802.11w", style="cyan")
                for b, i in networks.items(): table.add_row(b, i[0], str(i[1]), str(i[2]), i[3])
                layout["mid"].update(table)
                layout["bot"].update(Panel("\n".join(log_messages), title="Intelligence Stream", border_style="green"))
                time.sleep(1)
    except KeyboardInterrupt:
        global stop_threads
        stop_threads = True
        console.print("\n[bold yellow]Session Interrupted. Generating Forensic Documentation...[/bold yellow]")
        
        reporter = PDFReporter()
        fname = reporter.generate_report(networks)
        console.print(f"[bold green]Report Signed & Saved: {fname}[/bold green]")

if __name__ == "__main__":
    main()
      
