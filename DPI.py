import subprocess
import re
import threading
from rich.console import Console
from rich.style import Style
from rich.align import Align
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt
from collections import defaultdict, deque
from datetime import datetime
import time
import os
import random
import sys

# Global variable for output file (will be set by user)
OUTPUT_FILE = "network_logs.txt"
BUFFER_SIZE = 500
FLOW_TIMEOUT = 300
ALERT_THRESHOLD = 20000

console = Console(record=True)

def display_banner():
    banner_lines = [
        "██████╗ ██████╗ ██╗    ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ ",
        "██╔══██╗██╔══██╗██║    ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗",
        "██║  ██║██████╔╝██║    ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝",
        "██║  ██║██╔═══╝ ██║    ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗",
        "██████╔╝██║     ██║    ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║",
        "╚═════╝ ╚═╝     ╚═╝    ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝"
    ]

    colors = ["cyan", "bright_cyan", "blue", "bright_blue", "red", "bright_red"]

    console.print("\n", end="")

    for i, line in enumerate(banner_lines):
        gradient_line = Text()
        for j, char in enumerate(line):
            color_index = (i + j // 10) % len(colors)
            gradient_line.append(char, style=colors[color_index])
        console.print(Align.center(gradient_line))

    console.print("\n", end="")

    subtitle = Text()
    subtitle.append("═" * 20, style="bright_red")
    subtitle.append(" NETWORK DEEP PACKET INSPECTOR ", style="bold bright_white")
    subtitle.append("═" * 20, style="bright_red")
    console.print(Align.center(subtitle))

    console.print("\n", end="")

    author_text = Text()
    author_text.append("by ", style="dim white")
    author_text.append("0x1ez", style="bold bright_cyan")
    author_text.append(" • ", style="dim white")
    author_text.append("telegram ", style="dim white")
    author_text.append("@Mr_BOOND", style="bold bright_cyan")
    console.print(Align.center(author_text))

    console.print("\n", end="")

    matrix_line = Text()
    matrix_chars = "01"
    for _ in range(80):
        matrix_line.append(random.choice(matrix_chars), style=f"dim {'red' if random.random() > 0.5 else 'cyan'}")
    console.print(Align.center(matrix_line))

    console.print("\n", end="")

def process_tshark_warning(line):
    """Process and beautify tshark warning messages"""
    warning_style = Style(color="yellow", bold=True)
    info_style = Style(color="bright_magenta")
    danger_style = Style(color="red", bold=True)
    
    # Create a panel for the warning
    warning_panel = Panel.fit(
        "",
        border_style="yellow",
        title="[bold yellow]⚠ TShark Notice[/]",
        title_align="center"
    )
    
    if "Running as user" in line and "root" in line:
        warning_text = Text()
        warning_text.append("🔴 ", style="red")
        warning_text.append("Running as ", style="dim white")
        warning_text.append("ROOT", style="bold red blink")
        warning_text.append(" user\n", style="dim white")
        warning_text.append("   └─ ", style="dim yellow")
        warning_text.append("Elevated privileges detected", style="italic yellow")
        warning_text.append(" - Use with caution!", style="italic bright_yellow")
        
        warning_panel = Panel(
            warning_text,
            border_style="red",
            title="[bold red]⚡ Security Notice[/]",
            title_align="center",
            padding=(1, 2)
        )
        
    elif "Capturing on" in line:
        interface = line.split("'")[1] if "'" in line else "unknown"
        info_text = Text()
        info_text.append("🔍 ", style="cyan")
        info_text.append("Network Interface: ", style="dim white")
        info_text.append(interface, style="bold bright_cyan")
        info_text.append("\n   └─ ", style="dim cyan")
        info_text.append("Starting packet capture...", style="italic cyan")
        
        warning_panel = Panel(
            info_text,
            border_style="cyan",
            title="[bold cyan]📡 Interface Detection[/]",
            title_align="center",
            padding=(1, 2)
        )
        
    elif "arptype" in line and "not supported" in line:
        tech_text = Text()
        tech_text.append("⚙️  ", style="yellow")
        tech_text.append("ARP Type Issue Detected\n", style="bold yellow")
        tech_text.append("   ├─ ", style="dim yellow")
        tech_text.append("Problem: ", style="yellow")
        tech_text.append("arptype 519 not supported\n", style="bright_yellow")
        tech_text.append("   └─ ", style="dim yellow")
        tech_text.append("Solution: ", style="green")
        tech_text.append("Falling back to cooked socket mode", style="bright_green")
        
        warning_panel = Panel(
            tech_text,
            border_style="yellow",
            title="[bold yellow]🔧 Technical Adjustment[/]",
            title_align="center",
            padding=(1, 2)
        )
    else:
        # Generic warning
        warning_panel = Panel.fit(
            f"[yellow]{line.strip()}[/]",
            border_style="yellow",
            title="[bold yellow]ℹ️  TShark Info[/]",
            title_align="center"
        )
    
    console.print(warning_panel)
    console.print()

def get_output_filename():
    """Get output filename from user with validation"""
    console.print(Panel.fit(
        "[bold bright_white]📁 Output File Configuration[/]",
        border_style="bright_blue",
        padding=(0, 2)
    ))
    
    default_file = "network_logs.txt"
    
    console.print(f"\n[dim white]Default output file: [bold cyan]{default_file}[/][/]")
    console.print("[dim white]Press Enter to use default or type a new filename[/]\n")
    
    filename = Prompt.ask(
        "[bold bright_green]Enter output filename[/]",
        default=default_file,
        show_default=False
    )
    
    # Ensure .txt extension
    if not filename.endswith('.txt'):
        filename += '.txt'
    
    # Create directory if needed
    directory = os.path.dirname(filename)
    if directory and not os.path.exists(directory):
        try:
            os.makedirs(directory)
            console.print(f"[green]✓ Created directory: {directory}[/]")
        except Exception as e:
            console.print(f"[red]✗ Failed to create directory: {e}[/]")
            console.print(f"[yellow]↺ Using default: {default_file}[/]")
            filename = default_file
    
    console.print(f"\n[bold green]✓ Output will be saved to:[/] [bold bright_cyan]{filename}[/]\n")
    
    return filename

class FlowManager:
    def __init__(self):
        self.flows = defaultdict(lambda: {
            'count': 0,
            'bytes': 0,
            'start': time.time(),
            'last_seen': time.time(),
            'alerts': 0
        })
        self.lock = threading.Lock()

    def update_flow(self, flow_key, length):
        with self.lock:
            flow = self.flows[flow_key]
            flow['count'] += 1
            flow['bytes'] += int(length) if str(length).isdigit() else 0
            flow['last_seen'] = time.time()
            return flow

    def clean_old_flows(self):
        with self.lock:
            now = time.time()
            to_delete = [k for k, v in self.flows.items()
                        if (now - v['last_seen']) > FLOW_TIMEOUT]
            for k in to_delete:
                del self.flows[k]

    def check_alerts(self):
        alerts = []
        with self.lock:
            for flow_key, data in self.flows.items():
                if data['count'] > ALERT_THRESHOLD and data['alerts'] == 0:
                    alerts.append(flow_key)
                    data['alerts'] += 1
        return alerts

flow_mgr = FlowManager()

class DataHandler:
    def __init__(self):
        self.buffer = deque(maxlen=BUFFER_SIZE)
        self.lock = threading.Lock()
        self.unique_hosts = set()

    def add_data(self, items):
        with self.lock:
            new_items = [item for item in items if item not in self.unique_hosts]
            self.unique_hosts.update(new_items)
            self.buffer.extend(new_items)

    def save_to_file(self):
        with self.lock:
            if not self.buffer:
                return

            with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
                f.write("\n".join(self.buffer) + "\n")

            self.buffer.clear()

data_handler = DataHandler()

def background_tasks():
    while True:
        flow_mgr.clean_old_flows()

        alerts = flow_mgr.check_alerts()
        for flow_key in alerts:
            src_ip, src_port, dst_ip, dst_port, proto = flow_key
            console.print(
                f"[bold red]⚠ ALERT:[/] {dst_ip}:{dst_port} ({proto}) - "
                f"High traffic ({flow_mgr.flows[flow_key]['count']} packets)",
                style=Style(color="red", bold=True)
            )

        data_handler.save_to_file()
        time.sleep(30)

def parse_packet(line):
    try:
        parts = line.strip().split('|')
        parts += [''] * (14 - len(parts))
        return {
            'time': parts[0],
            'src_ip': parts[1],
            'dst_ip': parts[2],
            'tcp_sport': parts[3],
            'tcp_dport': parts[4],
            'udp_sport': parts[5],
            'udp_dport': parts[6],
            'dns_qry': parts[7],
            'dns_resp': parts[8],
            'tls_sni': parts[9],
            'http_host': parts[10],
            'http_code': parts[11],
            'ttl': parts[12],
            'length': parts[13]
        }
    except Exception as e:
        console.print(f"[red]Error parsing:[/] {str(e)}")
        return None

def process_packet(packet):
    collected = []

    if packet['dns_qry']:
        collected.append(packet['dns_qry'])
        console.print(
            f"{get_time(packet['time'])} | [cyan]◉ DNS-Query[/] | {packet['dns_qry']}",
            style=Style(color="cyan")
        )

    if packet['dns_resp']:
        ips = [ip.strip() for ip in packet['dns_resp'].split(',') if ip.strip()]
        collected.extend(ips)
        console.print(
            f"{get_time(packet['time'])} | [cyan]◈ DNS-Response[/] | {', '.join(ips)}",
            style=Style(color="bright_cyan")
        )

    if packet['tls_sni']:
        sni = packet['tls_sni'].split(':')[0]
        collected.append(sni)
        console.print(
            f"{get_time(packet['time'])} | [green]▶ TLS-SNI[/] | {sni}",
            style=Style(color="green")
        )

    if packet['http_host']:
        collected.append(packet['http_host'])
        console.print(
            f"{get_time(packet['time'])} | [magenta]★ HTTP-Host[/] | {packet['http_host']}",
            style=Style(color="magenta")
        )

    if packet['http_code']:
        color = "green" if packet['http_code'].startswith('2') else "red" if packet['http_code'].startswith(('4','5')) else "blue"
        console.print(
            f"{get_time(packet['time'])} | [{color}]● HTTP-{packet['http_code']}[/] | {packet['dst_ip']}",
            style=Style(color=color)
        )

    if collected:
        data_handler.add_data(collected)

    proto = 'TCP' if packet['tcp_sport'] else 'UDP' if packet['udp_sport'] else 'OTHER'
    flow_key = (
        packet['src_ip'],
        packet['tcp_sport'] or packet['udp_sport'],
        packet['dst_ip'],
        packet['tcp_dport'] or packet['udp_dport'],
        proto
    )
    flow_mgr.update_flow(flow_key, packet['length'])

def get_time(timestamp):
    try:
        return datetime.strptime(timestamp.split('.')[0], "%H:%M:%S").strftime("%H:%M:%S")
    except:
        return timestamp[:8]

def get_active_interface():
    try:
        result = subprocess.run(['ip', 'route', 'get', '1.1.1.1'], stdout=subprocess.PIPE, text=True)
        line = result.stdout.strip()
        if ' dev ' in line:
            iface = line.split(' dev ')[1].split()[0]
            return iface
    except Exception as e:
        print(f"Error detecting active interface: {e}")
    return 'wlan0'

def stderr_reader(proc):
    """Read stderr from tshark and display warnings beautifully"""
    for line in iter(proc.stderr.readline, ''):
        if line.strip():
            process_tshark_warning(line)

def main():
    global OUTPUT_FILE
    
    os.system('clear' if os.name != 'nt' else 'cls')
    display_banner()

    # Get output filename from user
    OUTPUT_FILE = get_output_filename()

    interface = get_active_interface()

    console.print(Panel.fit(
        f"[bold bright_cyan]Interface:[/] {interface}\n[bold bright_green]Output:[/] {OUTPUT_FILE}",
        border_style="bright_red",
        title="[bold white]📊 Configuration[/]",
        title_align="center"
    ))
    console.print()

    bg_thread = threading.Thread(target=background_tasks, daemon=True)
    bg_thread.start()

    with subprocess.Popen(
        ['tshark', '-i', interface, '-T', 'fields', '-e', 'frame.time',
         '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tcp.srcport', '-e', 'tcp.dstport',
         '-e', 'udp.srcport', '-e', 'udp.dstport', '-e', 'dns.qry.name',
         '-e', 'dns.a', '-e', 'tls.handshake.extensions_server_name',
         '-e', 'http.host', '-e', 'http.response.code', '-e', 'ip.ttl',
         '-e', 'frame.len', '-E', 'separator=|', '-l'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    ) as proc:

        # Start stderr reader thread
        stderr_thread = threading.Thread(target=stderr_reader, args=(proc,), daemon=True)
        stderr_thread.start()

        console.print(Panel.fit(
            "[bold green]▶ Started monitoring... (Ctrl+C to stop)[/]",
            border_style="green",
            title="[bold white]🎯 Status[/]",
            title_align="center"
        ))
        console.print()

        try:
            for line in iter(proc.stdout.readline, ''):
                packet = parse_packet(line)
                if packet:
                    process_packet(packet)

        except KeyboardInterrupt:
            console.print("\n")
            stop_panel = Panel.fit(
                "[bold yellow]⏸  Terminating safely...[/]",
                border_style="yellow",
                title="[bold white]🛑 Stopping[/]",
                title_align="center"
            )
            console.print(stop_panel)

        finally:
            proc.terminate()
            data_handler.save_to_file()
            
            # Final summary
            summary_text = Text()
            summary_text.append("✓ ", style="bold green")
            summary_text.append(f"Saved {len(data_handler.unique_hosts)} unique items\n", style="bright_white")
            summary_text.append("📄 ", style="bold blue")
            summary_text.append(f"Output file: {OUTPUT_FILE}\n", style="bright_cyan")
            summary_text.append("📊 ", style="bold magenta")
            summary_text.append(f"HTML report: network_report.html", style="bright_magenta")
            
            console.print("\n")
            console.print(Panel(
                summary_text,
                border_style="bright_green",
                title="[bold white]✨ Session Summary[/]",
                title_align="center",
                padding=(1, 2)
            ))
            
            console.save_html("network_report.html")

if __name__ == "__main__":
    main()
