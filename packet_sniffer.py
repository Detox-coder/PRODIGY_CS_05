#!/usr/bin/env python3
"""
PRODIGY_CS_05 - Network Packet Analyzer
===================================================
A comprehensive packet sniffer tool for educational purposes

Author: Amit Mondal - Cybersecurity Intern - Prodigy InfoTech
Date: June 2025
Version: 1.0

Features:
- Multi-layer dissection
- Application layer detection
- Real-time payload analysis
- Smart protocol identification
- Professional GUI Interface
- Security & Ethics Focus
- Technical Sophistication
"""

import sys
import threading
import time
from datetime import datetime
from collections import defaultdict
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import struct

# Check for required modules
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.dns import DNS, DNSQR
except ImportError:
    print("Error: Scapy library not found. Install with: pip install scapy")
    sys.exit(1)

class PacketAnalyzer:
    """Core packet analysis engine"""
    
    def __init__(self):
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        self.active_connections = set()
        
    def analyze_packet(self, packet):
        """Analyze individual packet and extract relevant information"""
        try:
            self.packet_count += 1
            analysis = {
                'id': self.packet_count,
                'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                'size': len(packet),
                'summary': packet.summary()
            }
            
            # Ethernet Layer Analysis
            if packet.haslayer('Ether'):
                analysis['eth_src'] = packet['Ether'].src
                analysis['eth_dst'] = packet['Ether'].dst
            
            # IP Layer Analysis
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                analysis.update({
                    'src_ip': ip_layer.src,
                    'dst_ip': ip_layer.dst,
                    'protocol': ip_layer.proto,
                    'ttl': ip_layer.ttl,
                    'length': ip_layer.len
                })
                
                # Protocol specific analysis
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    analysis.update({
                        'transport': 'TCP',
                        'src_port': tcp_layer.sport,
                        'dst_port': tcp_layer.dport,
                        'flags': tcp_layer.flags,
                        'seq': tcp_layer.seq,
                        'ack': tcp_layer.ack
                    })
                    
                    # HTTP Detection
                    if packet.haslayer(HTTPRequest):
                        http_req = packet[HTTPRequest]
                        analysis['app_protocol'] = 'HTTP Request'
                        analysis['http_method'] = http_req.Method.decode()
                        analysis['http_host'] = http_req.Host.decode() if http_req.Host else 'N/A'
                        analysis['http_path'] = http_req.Path.decode() if http_req.Path else '/'
                    
                    elif packet.haslayer(HTTPResponse):
                        analysis['app_protocol'] = 'HTTP Response'
                        analysis['http_status'] = packet[HTTPResponse].Status_Code.decode()
                
                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    analysis.update({
                        'transport': 'UDP',
                        'src_port': udp_layer.sport,
                        'dst_port': udp_layer.dport,
                        'length': udp_layer.len
                    })
                    
                    # DNS Detection
                    if packet.haslayer(DNS):
                        dns_layer = packet[DNS]
                        analysis['app_protocol'] = 'DNS'
                        if dns_layer.qr == 0:  # Query
                            analysis['dns_query'] = dns_layer[DNSQR].qname.decode().rstrip('.')
                        else:  # Response
                            analysis['dns_response'] = 'DNS Response'
                
                elif packet.haslayer(ICMP):
                    icmp_layer = packet[ICMP]
                    analysis.update({
                        'transport': 'ICMP',
                        'icmp_type': icmp_layer.type,
                        'icmp_code': icmp_layer.code
                    })
            
            # Payload Analysis
            if packet.haslayer('Raw'):
                raw_data = bytes(packet['Raw'])
                analysis['payload_size'] = len(raw_data)
                # Display first 50 bytes as hex
                analysis['payload_preview'] = raw_data[:50].hex()
                # Try to decode as ASCII (for readable content)
                try:
                    ascii_data = raw_data.decode('ascii', errors='ignore')[:100]
                    if ascii_data.isprintable():
                        analysis['payload_ascii'] = ascii_data
                except:
                    pass
            
            # Update statistics
            protocol_name = analysis.get('transport', 'Unknown')
            self.protocol_stats[protocol_name] += 1
            
            return analysis
            
        except Exception as e:
            return {'error': f'Analysis failed: {str(e)}', 'id': self.packet_count}

class PacketSnifferGUI:
    """Modern GUI interface for the packet sniffer"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("PRODIGY_CS_05 - Network Packet Analyzer")
        self.root.geometry("1400x900")
        self.root.configure(bg='#2b2b2b')
        
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()
        
        # Initialize components
        self.analyzer = PacketAnalyzer()
        self.sniffing = False
        self.sniffer_thread = None
        self.selected_interface = tk.StringVar()
        
        # GUI Setup
        self.create_widgets()
        self.show_ethical_disclaimer()
        self.refresh_interfaces()
        
    def configure_styles(self):
        """Configure custom styles for modern appearance"""
        self.style.configure('Title.TLabel', font=('Arial', 16, 'bold'), background='#2b2b2b', foreground='#ffffff')
        self.style.configure('Header.TLabel', font=('Arial', 12, 'bold'), background='#2b2b2b', foreground='#00ff88')
        self.style.configure('Info.TLabel', font=('Arial', 10), background='#2b2b2b', foreground='#ffffff')
        self.style.configure('Start.TButton', font=('Arial', 11, 'bold'))
        self.style.configure('Stop.TButton', font=('Arial', 11, 'bold'))
        
    def create_widgets(self):
        """Create and arrange GUI widgets"""
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Title
        title_label = ttk.Label(main_frame, text="🛡️ NETWORK PACKET ANALYZER", style='Title.TLabel')
        title_label.pack(pady=(0, 20))
        
        # Control Panel
        self.create_control_panel(main_frame)
        
        # Statistics Panel
        self.create_stats_panel(main_frame)
        
        # Packet Display
        self.create_packet_display(main_frame)
        
        # Status Bar
        self.create_status_bar(main_frame)
        
    def create_control_panel(self, parent):
        """Create control panel with interface selection and buttons"""
        control_frame = ttk.LabelFrame(parent, text="🔧 Control Panel", padding=10)
        control_frame.pack(fill='x', pady=(0, 10))
        
        # Interface Selection
        interface_frame = ttk.Frame(control_frame)
        interface_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(interface_frame, text="Network Interface:", style='Header.TLabel').pack(side='left')
        self.interface_combo = ttk.Combobox(interface_frame, textvariable=self.selected_interface, 
                                          width=30, state='readonly')
        self.interface_combo.pack(side='left', padx=(10, 0))
        
        refresh_btn = ttk.Button(interface_frame, text="🔄 Refresh", command=self.refresh_interfaces)
        refresh_btn.pack(side='left', padx=(10, 0))
        
        # Control Buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill='x')
        
        self.start_btn = ttk.Button(button_frame, text="▶️ START CAPTURE", 
                                   command=self.start_sniffing, style='Start.TButton')
        self.start_btn.pack(side='left', padx=(0, 10))
        
        self.stop_btn = ttk.Button(button_frame, text="⏹️ STOP CAPTURE", 
                                  command=self.stop_sniffing, style='Stop.TButton', state='disabled')
        self.stop_btn.pack(side='left', padx=(0, 10))
        
        clear_btn = ttk.Button(button_frame, text="🗑️ CLEAR", command=self.clear_display)
        clear_btn.pack(side='left', padx=(0, 10))
        
        # Filter Options
        filter_frame = ttk.Frame(control_frame)
        filter_frame.pack(fill='x', pady=(10, 0))
        
        ttk.Label(filter_frame, text="Filter:", style='Info.TLabel').pack(side='left')
        self.filter_var = tk.StringVar()
        filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, width=40)
        filter_entry.pack(side='left', padx=(10, 0))
        ttk.Label(filter_frame, text="(e.g., tcp, udp, host 192.168.1.1)", 
                 style='Info.TLabel').pack(side='left', padx=(10, 0))
        
    def create_stats_panel(self, parent):
        """Create statistics display panel"""
        stats_frame = ttk.LabelFrame(parent, text="📊 Live Statistics", padding=10)
        stats_frame.pack(fill='x', pady=(0, 10))
        
        self.stats_labels = {}
        stats_container = ttk.Frame(stats_frame)
        stats_container.pack(fill='x')
        
        # Create stats display
        for i, (key, label) in enumerate([
            ('packets', 'Total Packets'),
            ('tcp', 'TCP'),
            ('udp', 'UDP'),
            ('icmp', 'ICMP'),
            ('other', 'Other')
        ]):
            frame = ttk.Frame(stats_container)
            frame.pack(side='left', padx=(0, 20))
            
            ttk.Label(frame, text=f"{label}:", style='Info.TLabel').pack()
            self.stats_labels[key] = ttk.Label(frame, text="0", style='Header.TLabel')
            self.stats_labels[key].pack()
        
    def create_packet_display(self, parent):
        """Create packet display area"""
        display_frame = ttk.LabelFrame(parent, text="📦 Captured Packets", padding=10)
        display_frame.pack(fill='both', expand=True)
        
        # Create Treeview for packet list
        columns = ('ID', 'Time', 'Source IP', 'Dest IP', 'Protocol', 'Length', 'Info')
        self.packet_tree = ttk.Treeview(display_frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        column_widths = {'ID': 50, 'Time': 100, 'Source IP': 120, 'Dest IP': 120, 
                        'Protocol': 80, 'Length': 80, 'Info': 300}
        
        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=column_widths.get(col, 100))
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(display_frame, orient='vertical', command=self.packet_tree.yview)
        h_scrollbar = ttk.Scrollbar(display_frame, orient='horizontal', command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack treeview and scrollbars
        self.packet_tree.pack(side='left', fill='both', expand=True)
        v_scrollbar.pack(side='right', fill='y')
        h_scrollbar.pack(side='bottom', fill='x')
        
        # Bind selection event
        self.packet_tree.bind('<<TreeviewSelect>>', self.on_packet_select)
        
        # Packet details area
        details_frame = ttk.LabelFrame(parent, text="🔍 Packet Details", padding=10)
        details_frame.pack(fill='x', pady=(10, 0))
        
        self.details_text = scrolledtext.ScrolledText(details_frame, height=8, width=100,
                                                     bg='#1e1e1e', fg='#ffffff', font=('Consolas', 10))
        self.details_text.pack(fill='both', expand=True)
        
    def create_status_bar(self, parent):
        """Create status bar"""
        self.status_var = tk.StringVar()
        self.status_var.set("Ready - Select interface and click START to begin capturing")
        
        status_bar = ttk.Label(parent, textvariable=self.status_var, style='Info.TLabel', relief='sunken')
        status_bar.pack(fill='x', pady=(10, 0))
        
    def show_ethical_disclaimer(self):
        """Display ethical use disclaimer"""
        disclaimer = """
⚠️ ETHICAL USE DISCLAIMER ⚠️

This Network Packet Analyzer is designed for EDUCATIONAL PURPOSES ONLY.

IMPORTANT GUIDELINES:
• Only use this tool on networks you OWN or have EXPLICIT WRITTEN PERMISSION to monitor
• Unauthorized network monitoring is ILLEGAL and UNETHICAL
• This tool is for learning cybersecurity concepts and network analysis
• Always respect privacy and follow applicable laws and regulations
• Use responsibly and ethically

By clicking 'I Agree', you acknowledge that you understand and will comply with these guidelines.
        """
        
        result = messagebox.askyesno("Ethical Use Agreement", disclaimer)
        if not result:
            self.root.destroy()
            sys.exit()
    
    def refresh_interfaces(self):
        """Refresh available network interfaces"""
        try:
            interfaces = get_if_list()
            self.interface_combo['values'] = interfaces
            if interfaces:
                self.selected_interface.set(interfaces[0])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get interfaces: {str(e)}")
    
    def start_sniffing(self):
        """Start packet sniffing"""
        if not self.selected_interface.get():
            messagebox.showwarning("Warning", "Please select a network interface")
            return
        
        self.sniffing = True
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.status_var.set(f"Capturing packets on {self.selected_interface.get()}...")
        
        # Start sniffing in separate thread
        self.sniffer_thread = threading.Thread(target=self.packet_sniffer)
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()
        
    def stop_sniffing(self):
        """Stop packet sniffing"""
        self.sniffing = False
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.status_var.set("Packet capture stopped")
        
    def packet_sniffer(self):
        """Main packet sniffing function"""
        try:
            filter_str = self.filter_var.get().strip() if self.filter_var.get().strip() else None
            
            sniff(iface=self.selected_interface.get(),
                  prn=self.process_packet,
                  filter=filter_str,
                  stop_filter=lambda x: not self.sniffing,
                  store=0)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Sniffing failed: {str(e)}"))
            self.root.after(0, self.stop_sniffing)
    
    def process_packet(self, packet):
        """Process captured packet"""
        analysis = self.analyzer.analyze_packet(packet)
        
        # Update GUI in main thread
        self.root.after(0, lambda: self.update_display(analysis, packet))
        
    def update_display(self, analysis, packet):
        """Update GUI with packet information"""
        if 'error' in analysis:
            return
            
        # Insert into treeview
        values = (
            analysis.get('id', ''),
            analysis.get('timestamp', ''),
            analysis.get('src_ip', ''),
            analysis.get('dst_ip', ''),
            analysis.get('transport', 'Unknown'),
            analysis.get('size', ''),
            analysis.get('summary', '')[:50] + '...' if len(analysis.get('summary', '')) > 50 else analysis.get('summary', '')
        )
        
        item_id = self.packet_tree.insert('', 'end', values=values)
        
        # Store full analysis for details view
        self.packet_tree.set(item_id, 'analysis', analysis)
        
        # Auto-scroll to bottom
        self.packet_tree.see(item_id)
        
        # Update statistics
        self.update_statistics()
        
        # Update status
        self.status_var.set(f"Captured {self.analyzer.packet_count} packets")
        
    def update_statistics(self):
        """Update statistics display"""
        stats = self.analyzer.protocol_stats
        self.stats_labels['packets'].config(text=str(self.analyzer.packet_count))
        self.stats_labels['tcp'].config(text=str(stats.get('TCP', 0)))
        self.stats_labels['udp'].config(text=str(stats.get('UDP', 0)))
        self.stats_labels['icmp'].config(text=str(stats.get('ICMP', 0)))
        
        other_count = sum(v for k, v in stats.items() if k not in ['TCP', 'UDP', 'ICMP'])
        self.stats_labels['other'].config(text=str(other_count))
        
    def on_packet_select(self, event):
        """Handle packet selection for details view"""
        selection = self.packet_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        analysis = self.packet_tree.set(item, 'analysis')
        
        if analysis:
            self.show_packet_details(analysis)
    
    def show_packet_details(self, analysis):
        """Display detailed packet information"""
        self.details_text.delete(1.0, tk.END)
        
        details = f"""
📦 PACKET ANALYSIS DETAILS
{'='*60}

🔍 Basic Information:
   Packet ID: {analysis.get('id', 'N/A')}
   Timestamp: {analysis.get('timestamp', 'N/A')}
   Size: {analysis.get('size', 'N/A')} bytes
   Summary: {analysis.get('summary', 'N/A')}

🌐 Network Layer (IP):
   Source IP: {analysis.get('src_ip', 'N/A')}
   Destination IP: {analysis.get('dst_ip', 'N/A')}
   Protocol: {analysis.get('protocol', 'N/A')}
   TTL: {analysis.get('ttl', 'N/A')}
   Length: {analysis.get('length', 'N/A')}

🚛 Transport Layer:
   Protocol: {analysis.get('transport', 'N/A')}
   Source Port: {analysis.get('src_port', 'N/A')}
   Destination Port: {analysis.get('dst_port', 'N/A')}
        """
        
        # Add protocol-specific details
        if analysis.get('transport') == 'TCP':
            details += f"""
   TCP Flags: {analysis.get('flags', 'N/A')}
   Sequence Number: {analysis.get('seq', 'N/A')}
   Acknowledgment: {analysis.get('ack', 'N/A')}
            """
        elif analysis.get('transport') == 'ICMP':
            details += f"""
   ICMP Type: {analysis.get('icmp_type', 'N/A')}
   ICMP Code: {analysis.get('icmp_code', 'N/A')}
            """
        
        # Add application layer details
        if 'app_protocol' in analysis:
            details += f"""
📱 Application Layer:
   Protocol: {analysis.get('app_protocol', 'N/A')}
            """
            
            if 'http_method' in analysis:
                details += f"""
   HTTP Method: {analysis.get('http_method', 'N/A')}
   HTTP Host: {analysis.get('http_host', 'N/A')}
   HTTP Path: {analysis.get('http_path', 'N/A')}
                """
            elif 'dns_query' in analysis:
                details += f"""
   DNS Query: {analysis.get('dns_query', 'N/A')}
                """
        
        # Add payload information
        if 'payload_size' in analysis:
            details += f"""
📄 Payload Information:
   Payload Size: {analysis.get('payload_size', 'N/A')} bytes
   Hex Preview: {analysis.get('payload_preview', 'N/A')}
            """
            
            if 'payload_ascii' in analysis:
                details += f"""
   ASCII Preview: {analysis.get('payload_ascii', 'N/A')}
                """
        
        self.details_text.insert(tk.END, details)
        
    def clear_display(self):
        """Clear packet display and reset statistics"""
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.details_text.delete(1.0, tk.END)
        self.analyzer = PacketAnalyzer()
        self.update_statistics()
        self.status_var.set("Display cleared - Ready for new capture")
        
    def run(self):
        """Start the GUI application"""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            print("\nShutting down...")
            self.stop_sniffing()

def main():
    """Main function"""
    print("PRODIGY_CS_05 - Network Packet Analyzer")
    print("=" * 50)
    print("Starting GUI application...")
    
    # Check if running with proper permissions
    try:
        # Test socket creation for raw packet access
        test_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        test_socket.close()
    except PermissionError:
        print("⚠️  Warning: This tool requires administrator/root privileges for packet capture.")
        print("   Please run with 'sudo' on Linux/Mac or as Administrator on Windows.")
    except OSError:
        pass  # Different OS, different requirements
    
    # Start GUI
    app = PacketSnifferGUI()
    app.run()

if __name__ == "__main__":
    main()