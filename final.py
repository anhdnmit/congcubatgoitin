import time
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
import socket
import struct
import psutil
import fcntl

#############################################################
# Các lớp phân tích gói tin: Ether, IP, TCP, UDP, ARP, …
#############################################################

class Ether:
    def __init__(self, dest, src, type):
        self.dst = self.mac_addr(dest)
        self.src = self.mac_addr(src)
        self.type = type
    def mac_addr(self, bytes_addr):
        return ':'.join('%02x' % b for b in bytes_addr)
    def __str__(self):
        return f"Ether(src={self.src}, dst={self.dst}, type=0x{self.type:04x})"

class IP:
    def __init__(self, data):
        self.data = data
        self.version = data[0] >> 4
        self.ihl = data[0] & 0x0F
        header_length = self.ihl * 4
        ip_header = data[:header_length]
        self.tos = ip_header[1]
        self.len = struct.unpack('!H', ip_header[2:4])[0]
        self.id = struct.unpack('!H', ip_header[4:6])[0]
        frag_field = struct.unpack('!H', ip_header[6:8])[0]
        self.flags = (frag_field >> 13) & 0x7
        self.frag_offset = frag_field & 0x1FFF
        self.ttl = ip_header[8]
        self.protocol = ip_header[9]
        self.checksum = struct.unpack('!H', ip_header[10:12])[0]
        self.src = socket.inet_ntoa(ip_header[12:16])
        self.dst = socket.inet_ntoa(ip_header[16:20])
        self.payload = data[header_length:]
    def __str__(self):
        return f"IP(src={self.src}, dst={self.dst}, proto={self.protocol})"

class IPv6:
    def __init__(self, data):
        self.data = data
        header = data[:40]
        self.nh = header[6]
        self.src = socket.inet_ntop(socket.AF_INET6, header[8:24])
        self.dst = socket.inet_ntop(socket.AF_INET6, header[24:40])
        self.payload = data[40:]
    def __str__(self):
        return f"IPv6(src={self.src}, dst={self.dst}, nh={self.nh})"

class TCP:
    def __init__(self, data):
        header = data[:20]
        fields = struct.unpack("!HHLLBBHHH", header)
        self.sport = fields[0]
        self.dport = fields[1]
        self.seq = fields[2]
        self.ack = fields[3]
        data_offset_reserved = fields[4]
        self.data_offset = (data_offset_reserved >> 4)
        self.reserved = (data_offset_reserved & 0x0F)
        self.flags = fields[5]
        self.window = fields[6]
        self.checksum = fields[7]
        self.urg_ptr = fields[8]
        tcp_header_len = self.data_offset * 4
        self.payload = data[tcp_header_len:]
    def __str__(self):
        return f"TCP(sport={self.sport}, dport={self.dport})"

class UDP:
    def __init__(self, data):
        header = data[:8]
        fields = struct.unpack("!HHHH", header)
        self.sport = fields[0]
        self.dport = fields[1]
        self.length = fields[2]
        self.checksum = fields[3]
        self.payload = data[8:]
    def __str__(self):
        return f"UDP(sport={self.sport}, dport={self.dport})"

class ARP:
    def __init__(self, data):
        header = data[:28]
        fields = struct.unpack("!HHBBH6s4s6s4s", header)
        self.hwtype = fields[0]
        self.proto = fields[1]
        self.hwlen = fields[2]
        self.protolen = fields[3]
        self.opcode = fields[4]
        self.src_mac = self.mac_addr(fields[5])
        self.src_ip = socket.inet_ntoa(fields[6])
        self.dst_mac = self.mac_addr(fields[7])
        self.dst_ip = socket.inet_ntoa(fields[8])
    def mac_addr(self, bytes_addr):
        return ':'.join('%02x' % b for b in bytes_addr)
    def __str__(self):
        return f"ARP(opcode={self.opcode}, src_ip={self.src_ip}, dst_ip={self.dst_ip})"

class ICMP:
    def __init__(self, data):
        header = data[:4]
        fields = struct.unpack("!BBH", header)
        self.type = fields[0]
        self.code = fields[1]
        self.checksum = fields[2]
        self.payload = data[4:]
    def __str__(self):
        return f"ICMP(type={self.type}, code={self.code})"

class ICMPv6ND_NS:
    def __init__(self, data):
        self.data = data
    def __str__(self):
        return "ICMPv6ND_NS"

class HTTPRequest:
    def __init__(self, data):
        self.data = data
    def __str__(self):
        return "HTTPRequest"

class DNS:
    def __init__(self, data):
        self.data = data
    def __str__(self):
        return "DNS"

class Packet:
    def __init__(self, raw_data, ts=None):
        self.raw = raw_data
        self.timestamp = ts if ts is not None else time.time()
        self.layers = {}
        self.parse()
    def parse(self):
        data = self.raw
        if len(data) >= 14:
            try:
                eth_header = data[:14]
                dest_mac, src_mac, proto = struct.unpack("!6s6sH", eth_header)
                self.layers[Ether] = Ether(dest_mac, src_mac, proto)
                data = data[14:]
            except Exception as e:
                pass
            if Ether in self.layers and self.layers[Ether].type == 0x0806:
                if len(data) >= 28:
                    try:
                        arp_obj = ARP(data)
                        self.layers[ARP] = arp_obj
                    except:
                        pass
                return
        if len(data) >= 20:
            version = data[0] >> 4
            if version == 4:
                ip_obj = IP(data)
                self.layers[IP] = ip_obj
                if ip_obj.protocol == 6 and len(ip_obj.payload) >= 20:
                    tcp_obj = TCP(ip_obj.payload)
                    self.layers[TCP] = tcp_obj
                    if tcp_obj.payload.startswith(b"GET") or tcp_obj.payload.startswith(b"POST") or tcp_obj.payload.startswith(b"HTTP"):
                        self.layers[HTTPRequest] = HTTPRequest(tcp_obj.payload)
                elif ip_obj.protocol == 17 and len(ip_obj.payload) >= 8:
                    udp_obj = UDP(ip_obj.payload)
                    self.layers[UDP] = udp_obj
                    if udp_obj.sport == 53 or udp_obj.dport == 53:
                        self.layers[DNS] = DNS(udp_obj.payload)
                elif ip_obj.protocol == 1:
                    self.layers[ICMP] = ICMP(ip_obj.payload)
            elif version == 6 and len(data) >= 40:
                ipv6_obj = IPv6(data)
                self.layers[IPv6] = ipv6_obj
                if ipv6_obj.nh == 6 and len(ipv6_obj.payload) >= 20:
                    tcp_obj = TCP(ipv6_obj.payload)
                    self.layers[TCP] = tcp_obj
                    if tcp_obj.payload.startswith(b"GET") or tcp_obj.payload.startswith(b"POST") or tcp_obj.payload.startswith(b"HTTP"):
                        self.layers[HTTPRequest] = HTTPRequest(tcp_obj.payload)
                elif ipv6_obj.nh == 17 and len(ipv6_obj.payload) >= 8:
                    udp_obj = UDP(ipv6_obj.payload)
                    self.layers[UDP] = udp_obj
                    if udp_obj.sport == 53 or udp_obj.dport == 53:
                        self.layers[DNS] = DNS(udp_obj.payload)
                elif ipv6_obj.nh == 58:
                    self.layers[ICMPv6ND_NS] = ICMPv6ND_NS(ipv6_obj.payload)
        else:
            try:
                ip_obj = IP(data)
                self.layers[IP] = ip_obj
            except:
                pass
    def haslayer(self, layer_cls):
        return layer_cls in self.layers
    def __getitem__(self, layer_cls):
        return self.layers.get(layer_cls, None)
    
    def show(self, dump=False):
        s = ""
        if Ether in self.layers:
            e = self.layers[Ether]
            s += "###[ Ether ]###\n"
            s += f"  dst = {e.dst}\n"
            s += f"  src = {e.src}\n"
            s += f"  type= 0x{e.type:04x}\n\n"
        if ARP in self.layers:
            arp = self.layers[ARP]
            s += "###[ ARP ]###\n"
            s += f"  hwtype   = {arp.hwtype}\n"
            s += f"  proto    = {arp.proto}\n"
            s += f"  hwlen    = {arp.hwlen}\n"
            s += f"  protolen = {arp.protolen}\n"
            s += f"  opcode   = {arp.opcode}\n"
            s += f"  src_mac  = {arp.src_mac}\n"
            s += f"  src_ip   = {arp.src_ip}\n"
            s += f"  dst_mac  = {arp.dst_mac}\n"
            s += f"  dst_ip   = {arp.dst_ip}\n\n"
        if IP in self.layers:
            i = self.layers[IP]
            s += "###[ IP ]###\n"
            s += f"  version   = {i.version}\n"
            s += f"  ihl       = {i.ihl}\n"
            s += f"  tos       = {i.tos}\n"
            s += f"  len       = {i.len}\n"
            s += f"  id        = {i.id}\n"
            s += f"  flags     = {i.flags}\n"
            s += f"  frag      = {i.frag_offset}\n"
            s += f"  ttl       = {i.ttl}\n"
            s += f"  proto     = {i.protocol}\n"
            s += f"  chksum    = {i.checksum}\n"
            s += f"  src       = {i.src}\n"
            s += f"  dst       = {i.dst}\n\n"
        if IPv6 in self.layers:
            v6 = self.layers[IPv6]
            s += "###[ IPv6 ]###\n"
            s += f"  nh        = {v6.nh}\n"
            s += f"  src       = {v6.src}\n"
            s += f"  dst       = {v6.dst}\n\n"
        if TCP in self.layers:
            t = self.layers[TCP]
            s += "###[ TCP ]###\n"
            s += f"  sport     = {t.sport}\n"
            s += f"  dport     = {t.dport}\n"
            s += f"  seq       = {t.seq}\n"
            s += f"  ack       = {t.ack}\n"
            s += f"  dataofs   = {t.data_offset}\n"
            s += f"  reserved  = {t.reserved}\n"
            s += f"  flags     = {t.flags}\n"
            s += f"  window    = {t.window}\n"
            s += f"  chksum    = {t.checksum}\n"  # Đã sửa tại đây
            s += f"  urgptr    = {t.urg_ptr}\n\n"
            if t.payload:
                s += "###[ Padding ]###\n"
                s += f"  load = {t.payload}\n\n"
        if s == "":
            s = "Packet with unknown layers\n"
        return s


#############################################################
# Các hàm hỗ trợ: set_promiscuous_mode, sniff, wrpcap, rdpcap, get_linux_if_list
#############################################################

def set_promiscuous_mode(ifname):
    SIOCGIFFLAGS = 0x8913  
    SIOCSIFFLAGS = 0x8914  
    IFF_PROMISC = 0x100    
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack('16sH', ifname.encode('utf-8'), 0)
    try:
        res = fcntl.ioctl(sockfd, SIOCGIFFLAGS, ifreq)
    except Exception as e:
        print("Lỗi khi lấy flag của giao diện:", e)
        sockfd.close()
        return
    flags = struct.unpack('16sH', res)[1]
    flags |= IFF_PROMISC
    ifreq = struct.pack('16sH', ifname.encode('utf-8'), flags)
    try:
        fcntl.ioctl(sockfd, SIOCSIFFLAGS, ifreq)
    except Exception as e:
        print("Lỗi khi bật chế độ promiscuous:", e)
    sockfd.close()

def sniff(iface, prn, store=True, stop_flag=lambda: False):
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except Exception as e:
        print("Socket creation failed:", e)
        return []
    try:
        set_promiscuous_mode(iface)
    except Exception as e:
        print("Failed to set promiscuous mode:", e)
    try:
        s.bind((iface, 0))
    except Exception as e:
        print("Socket bind failed:", e)
        s.close()
        return []
    s.settimeout(1.0)
    captured_packets = []
    try:
        while not stop_flag():
            try:
                raw_data, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            packet = Packet(raw_data)
            prn(packet)
            if store:
                captured_packets.append(packet)
    finally:
        s.close()
    return captured_packets

def wrpcap(filename, packets):
    with open(filename, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for packet in packets:
            ts = int(packet.timestamp)
            ts_usec = int((packet.timestamp - ts) * 1000000)
            raw_data = packet.raw
            incl_len = len(raw_data)
            orig_len = len(raw_data)
            f.write(struct.pack("<IIII", ts, ts_usec, incl_len, orig_len))
            f.write(raw_data)

def rdpcap(filename):
    packets = []
    with open(filename, "rb") as f:
        f.read(24)
        while True:
            pkt_header = f.read(16)
            if len(pkt_header) < 16:
                break
            ts, ts_usec, incl_len, orig_len = struct.unpack("<IIII", pkt_header)
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break
            pkt = Packet(pkt_data, ts + ts_usec/1000000.0)
            packets.append(pkt)
    return packets

def get_linux_if_list():
    interfaces = []
    try:
        for iface in psutil.net_if_addrs().keys():
            interfaces.append({'name': iface, 'description': iface})
    except Exception as e:
        interfaces = [{'name': 'lo', 'description': 'lo'}]
    return interfaces

#############################################################
# Giao diện ứng dụng (PacketSnifferApp)
#############################################################

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Công cụ bắt gói tin")
        self.root.geometry("1200x700")
        self.root.configure(bg="#282C34")
        
        self.style = ttk.Style()
        self.style.configure("TButton", font=("Segoe UI", 10), padding=5)
        
        control_frame = tk.Frame(root, bg="#282C34")
        control_frame.pack(fill=tk.X, padx=10, pady=5)

        self.interface_var = tk.StringVar()
        self.interface_menu = ttk.Combobox(control_frame, textvariable=self.interface_var,
                                           values=self.get_network_interfaces(), state="readonly", width=20)
        self.interface_menu.pack(side=tk.LEFT, padx=5)
        
        self.start_button = ttk.Button(control_frame, text="Bắt đầu", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=3)
        self.stop_button = ttk.Button(control_frame, text="Dừng lại", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=3)
        self.save_button = ttk.Button(control_frame, text="Lưu PCAP", command=self.save_pcap)
        self.save_button.pack(side=tk.LEFT, padx=3)
        self.load_button = ttk.Button(control_frame, text="Mở PCAP", command=self.load_pcap)
        self.load_button.pack(side=tk.LEFT, padx=3)
        self.reset_button = ttk.Button(control_frame, text="Khởi động lại", command=self.reset_sniffing)
        self.reset_button.pack(side=tk.LEFT, padx=3)

        # Combobox cho chức năng thống kê (Cập nhật thêm "Thống kê cuộc hội thoại")
        self.stats_options = ["Thống kê điểm đến", "Thống kê giao thức", "Thống kê cuộc hội thoại"]
        self.stats_var = tk.StringVar(value="Chọn thống kê")
        self.stats_combobox = ttk.Combobox(control_frame, textvariable=self.stats_var,
                                           values=self.stats_options, state="readonly", width=20)
        self.stats_combobox.pack(side=tk.LEFT, padx=5)
        self.stats_combobox.bind("<<ComboboxSelected>>", self.execute_stats)

        self.paned_window = tk.PanedWindow(root, orient=tk.VERTICAL, bg="#282C34")
        self.paned_window.pack(fill=tk.BOTH, expand=True, padx=3, pady=5)

        frame_tree = tk.Frame(self.paned_window, bg="#282C34")
        self.tree = ttk.Treeview(frame_tree, columns=("Time", "Source", "Destination", "Protocol"), show="headings", height=10)
        self.tree.heading("Time", text="Thời gian")
        self.tree.heading("Source", text="Địa chỉ nguồn")
        self.tree.heading("Destination", text="Địa chỉ đích")
        self.tree.heading("Protocol", text="Giao thức")
        scroll_tree_y = ttk.Scrollbar(frame_tree, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll_tree_y.set)
        scroll_tree_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)
        frame_tree.pack(fill=tk.BOTH, expand=True)
        self.paned_window.add(frame_tree)

        frame_text = tk.Frame(self.paned_window, bg="#282C34")
        self.text_area = scrolledtext.ScrolledText(frame_text, height=5, bg="#21252B", fg="white", font=("Courier", 10))
        self.text_area.pack(fill=tk.BOTH, expand=True)
        frame_text.pack(fill=tk.BOTH, expand=True)
        self.paned_window.add(frame_text)

        self.sniffing = False
        self.packets = []
        self.capture_start_time = None  # Thời điểm bắt đầu bắt gói tin
        self.tree.bind("<ButtonRelease-1>", self.display_packet_details)
        self.stats_window = None  # Biến để lưu cửa sổ thống kê hiện tại

    def get_network_interfaces(self):
        self.iface_map = {}
        interface_names = []
        interfaces = get_linux_if_list()
        interface_names.append("Tất cả card mạng")
        self.iface_map["Tất cả card mạng"] = [iface['name'] for iface in interfaces]
        for iface in interfaces:
            display_name = f"{iface['name']} - {iface['description']}"
            interface_names.append(display_name)
            self.iface_map[display_name] = iface['name']
        return interface_names

    def start_sniffing(self):
        selected_name = self.interface_var.get()
        if not selected_name:
            messagebox.showerror("Error", "Vui lòng chọn một giao diện!")
            return
        self.sniffing = True
        self.capture_start_time = time.time()  # Lưu thời điểm bắt đầu bắt gói tin
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        if selected_name == "Tất cả card mạng":
            for iface in self.iface_map["Tất cả card mạng"]:
                threading.Thread(target=self.sniff_packets, args=(iface,), daemon=True).start()
        else:
            iface_device = self.iface_map.get(selected_name)
            if not iface_device:
                messagebox.showerror("Error", "Không tìm thấy giao diện.")
                return
            threading.Thread(target=self.sniff_packets, args=(iface_device,), daemon=True).start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self, iface):
        self.packets += sniff(iface=iface, prn=self.process_packet, store=True, stop_flag=lambda: not self.sniffing)

    # def process_packet(self, packet):
    #     if not self.sniffing:
    #         return
    #     src = "Unknown"
    #     dst = "Unknown"
    #     if packet.haslayer(Ether):
    #         ether_layer = packet[Ether]
    #         src = ether_layer.src
    #         dst = ether_layer.dst
    #     if packet.haslayer(ARP):
    #         src = packet[ARP].src_ip
    #         dst = packet[ARP].dst_ip
    #     elif packet.haslayer(IP):
    #         src = packet[IP].src
    #         dst = packet[IP].dst
    #     elif packet.haslayer(IPv6):
    #         src = packet[IPv6].src
    #         dst = packet[IPv6].dst
    #     timestamp = time.strftime('%H:%M:%S')
    #     protocol = self.identify_protocol(packet)
    #     self.tree.insert("", tk.END, values=(timestamp, src, dst, protocol))
    def process_packet(self, packet):
        if not self.sniffing:
            return
        # Lấy thông tin nguồn và đích của gói tin
        src = "Unknown"
        dst = "Unknown"
        if packet.haslayer(Ether):
            ether_layer = packet[Ether]
            src = ether_layer.src
            dst = ether_layer.dst
        if packet.haslayer(ARP):
            src = packet[ARP].src_ip
            dst = packet[ARP].dst_ip
        elif packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
        elif packet.haslayer(IPv6):
            src = packet[IPv6].src
            dst = packet[IPv6].dst
        # Lấy thời gian và giao thức của gói tin
        timestamp = time.strftime('%H:%M:%S')
        protocol = self.identify_protocol(packet)
        # Thêm gói tin vào bảng Treeview
        self.tree.insert("", tk.END, values=(timestamp, src, dst, protocol))
        
        # Đảm bảo luôn thêm gói tin vào danh sách gói tin
        self.packets.append(packet)

        # Nếu muốn tự động hiển thị chi tiết gói tin sau mỗi lần bắt (không dừng lại)
        self.display_packet_details(None)  # Giả sử có thể gọi hàm này trực tiếp để hiển thị chi tiết


    def identify_protocol(self, packet):
        if packet.haslayer(ARP):
            return "ARP"
        elif packet.haslayer(HTTPRequest):
            return "HTTP"
        elif packet.haslayer(DNS):
            return "DNS"
        elif packet.haslayer(TCP):
            dport = packet[TCP].dport if packet.haslayer(TCP) else 0
            if dport == 21:
                return "FTP"
            elif dport == 110:
                return "POP3"
            elif dport == 25:
                return "SMTP"
            elif dport == 23:
                return "Telnet"
            elif dport == 22:
                return "SSH"
            elif dport == 445:
                return "SMB"
            elif dport == 443:
                return "HTTPS"
            return "TCP"
        elif packet.haslayer(UDP):
            return "UDP"
        elif packet.haslayer(ICMP):
            return "ICMP"
        elif packet.haslayer(ICMPv6ND_NS):
            return "ICMPv6"
        return "Other"

    # def display_packet_details(self, event):
    #     selected_item = self.tree.selection()
    #     if selected_item:
    #         index = self.tree.index(selected_item[0])
    #         packet = self.packets[index]
    #         self.text_area.delete("1.0", tk.END)
    #         self.text_area.insert(tk.END, packet.show(dump=True))
    def display_packet_details(self, event):
        # Nếu không có gói tin thì không làm gì
        selected_item = self.tree.selection()
        if selected_item:
            try:
                # Lấy chỉ mục gói tin đã chọn trong Treeview
                index = self.tree.index(selected_item[0])
                packet = self.packets[index]
                # Xóa và chèn chi tiết gói tin vào vùng text
                self.text_area.delete("1.0", tk.END)
                self.text_area.insert(tk.END, packet.show(dump=True))
            except IndexError:
                print("Lỗi: Không tìm thấy gói tin!")
        else:
            print("Lỗi: Không có gói tin được chọn!")


    def save_pcap(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
        if file_path:
            wrpcap(file_path, self.packets)
            messagebox.showinfo("Save", "Gói tin đã được lưu thành công!")

    def load_pcap(self):
        file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
        if file_path:
            self.packets = rdpcap(file_path)
            self.tree.delete(*self.tree.get_children())
            for packet in self.packets:
                if packet.haslayer(IP):
                    src = packet[IP].src
                    dst = packet[IP].dst
                elif packet.haslayer(IPv6):
                    src = packet[IPv6].src
                    dst = packet[IPv6].dst
                elif packet.haslayer(ARP):
                    src = packet[ARP].src_ip
                    dst = packet[ARP].dst_ip
                else:
                    src = "Unknown"
                    dst = "Unknown"
                timestamp = time.strftime('%H:%M:%S')
                protocol = self.identify_protocol(packet)
                self.tree.insert("", tk.END, values=(timestamp, src, dst, protocol))
            # Cập nhật lại capture_start_time từ gói tin đầu tiên nếu load PCAP
            if self.packets:
                self.capture_start_time = min(p.timestamp for p in self.packets)
            messagebox.showinfo("Load", "Gói tin đã được tải thành công!")

    def execute_stats(self, event):
        option = self.stats_var.get()
        # Nếu đã có cửa sổ thống kê mở, đóng nó lại trước
        if self.stats_window is not None and self.stats_window.winfo_exists():
            self.stats_window.destroy()
            self.stats_window = None
        if option == "Thống kê điểm đến":
            self.show_destination_stats()
        elif option == "Thống kê giao thức":
            self.show_protocol_stats()
        elif option == "Thống kê cuộc hội thoại":
            self.show_conversation_stats()

    def show_destination_stats(self):
        if not self.packets:
            messagebox.showwarning("Cảnh báo", "Không có gói tin để thống kê!")
            return
        df = pd.DataFrame({"Destination": [p[IP].dst for p in self.packets if p.haslayer(IP)]})
        destination_frequency = df["Destination"].value_counts()
        destination_frequency = destination_frequency[destination_frequency >= 10]
        if destination_frequency.empty:
            messagebox.showinfo("Thông báo", "Không có địa chỉ đích nào có tần suất trên 10!")
            return
        # Tạo cửa sổ thống kê Toplevel
        self.stats_window = tk.Toplevel(self.root)
        self.stats_window.title("Thống kê điểm đến")
        fig, ax = plt.subplots(figsize=(10, 5))
        destination_frequency.plot(kind="bar", ax=ax)
        ax.set_xlabel("Destination")
        ax.set_ylabel("Frequency")
        ax.set_title("Tần suất các địa chỉ đích xuất hiện")
        for tick in ax.get_xticklabels():
            tick.set_rotation(45)
        canvas = FigureCanvasTkAgg(fig, master=self.stats_window)
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        canvas.draw()

    def show_protocol_stats(self):
        if not self.packets:
            messagebox.showwarning("Cảnh báo", "Không có gói tin để thống kê!")
            return
        self.stats_window = tk.Toplevel(self.root)
        self.stats_window.title("Thống kê giao thức")
        self.stats_window.geometry("600x400")
        df = pd.DataFrame({"protocol": [self.identify_protocol(p) for p in self.packets]})
        protocol_counts = df["protocol"].value_counts()
        fig, ax = plt.subplots(figsize=(6, 4))
        protocol_counts.plot(kind="bar", ax=ax)
        ax.set_title("Phân phối Giao thức")
        ax.set_xlabel("Giao thức")
        ax.set_ylabel("Số lượng")
        for tick in ax.get_xticklabels():
            tick.set_rotation(0)
        canvas = FigureCanvasTkAgg(fig, master=self.stats_window)
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        canvas.draw()

    # Hàm thống kê cuộc hội thoại theo các cột đã yêu cầu
        # Trong lớp PacketSnifferApp, cập nhật execute_stats như sau:
    def execute_stats(self, event):
        option = self.stats_var.get()
        # Nếu đã có cửa sổ thống kê mở, đóng lại trước
        if self.stats_window is not None and self.stats_window.winfo_exists():
            self.stats_window.destroy()
            self.stats_window = None
        if option == "Thống kê điểm đến":
            self.show_destination_stats()
        elif option == "Thống kê giao thức":
            self.show_protocol_stats()
        elif option == "Thống kê cuộc hội thoại":
            self.show_conversation_stats_selector()
    
    # Cửa sổ để lựa chọn giao thức cho thống kê cuộc hội thoại
    def show_conversation_stats_selector(self):
        selector = tk.Toplevel(self.root)
        selector.title("Chọn giao thức cho thống kê cuộc hội thoại")
        tk.Label(selector, text="Chọn giao thức phân tích cuộc hội thoại:").pack(padx=10, pady=10)
        protocol_var = tk.StringVar(value="Ethernet")
        tk.Radiobutton(selector, text="Ethernet", variable=protocol_var, value="Ethernet").pack(padx=10, pady=5)
        tk.Radiobutton(selector, text="TCP", variable=protocol_var, value="TCP").pack(padx=10, pady=5)
        def on_select():
            proto = protocol_var.get()
            selector.destroy()
            if proto == "Ethernet":
                self.show_ethernet_conversation_stats()
            elif proto == "TCP":
                self.show_tcp_conversation_stats()
        tk.Button(selector, text="Xem thống kê", command=on_select).pack(padx=10, pady=10)
    
    # Hàm thống kê cuộc hội thoại theo giao thức Ethernet (dựa vào lớp Ether)
    def show_ethernet_conversation_stats(self):
        if not self.packets:
            messagebox.showwarning("Cảnh báo", "Không có gói tin để thống kê!")
            return
        if not self.capture_start_time:
            self.capture_start_time = min(p.timestamp for p in self.packets)
        conv_dict = {}
        for p in self.packets:
            if not p.haslayer(Ether):
                continue
            macA, macB = sorted([p[Ether].src, p[Ether].dst])
            key = (macA, macB)
            if key not in conv_dict:
                conv_dict[key] = {
                    "packets_total": 0,
                    "bytes_total": 0,
                    "packets_A_to_B": 0,
                    "bytes_A_to_B": 0,
                    "packets_B_to_A": 0,
                    "bytes_B_to_A": 0,
                    "first_timestamp": p.timestamp,
                    "last_timestamp": p.timestamp,
                    "stream_id": None
                }
            conv = conv_dict[key]
            conv["packets_total"] += 1
            pkt_len = len(p.raw)
            conv["bytes_total"] += pkt_len
            conv["first_timestamp"] = min(conv["first_timestamp"], p.timestamp)
            conv["last_timestamp"] = max(conv["last_timestamp"], p.timestamp)
            if p[Ether].src == macA:
                conv["packets_A_to_B"] += 1
                conv["bytes_A_to_B"] += pkt_len
            else:
                conv["packets_B_to_A"] += 1
                conv["bytes_B_to_A"] += pkt_len
            if p.haslayer(UDP):  # Nếu có lớp UDP, xác định Stream ID
                udp = p[UDP]
                candidate = f"{min(udp.sport, udp.dport)}<->{max(udp.sport, udp.dport)}"
                if conv["stream_id"] is None:
                    conv["stream_id"] = candidate
                elif conv["stream_id"] != candidate:
                    conv["stream_id"] = "Multiple"
        records = []
        for (macA, macB), conv in conv_dict.items():
            duration = conv["last_timestamp"] - conv["first_timestamp"]
            rel_start = conv["first_timestamp"] - self.capture_start_time
            bits_A_to_B = (conv["bytes_A_to_B"] * 8 / duration) if duration > 0 else 0
            bits_B_to_A = (conv["bytes_B_to_A"] * 8 / duration) if duration > 0 else 0
            record = {
                "Address A": macA,
                "Address B": macB,
                "Packets": conv["packets_total"],
                "Bytes": conv["bytes_total"],
                "Stream ID": conv["stream_id"] if conv["stream_id"] is not None else "",
                "Packets A→B": conv["packets_A_to_B"],
                "Bytes A→B": conv["bytes_A_to_B"],
                "Packets B→A": conv["packets_B_to_A"],
                "Bytes B→A": conv["bytes_B_to_A"],
                "Rel Start": f"{rel_start:.3f}",
                "Duration": f"{duration:.3f}",
                "Bits/s A→B": f"{bits_A_to_B:.2f}",
                "Bits/s B→A": f"{bits_B_to_A:.2f}",
                "Flows": 1
            }
            records.append(record)
        stats_win = tk.Toplevel(self.root)
        stats_win.title("Thống kê cuộc hội thoại (Ethernet)")
        cols = ["Address A", "Address B", "Packets", "Bytes", "Stream ID", 
                "Packets A→B", "Bytes A→B", "Packets B→A", "Bytes B→A", 
                "Rel Start", "Duration", "Bits/s A→B", "Bits/s B→A", "Flows"]
        tree = ttk.Treeview(stats_win, columns=cols, show="headings")
        for col in cols:
            tree.heading(col, text=col)
            tree.column(col, width=100)
        for rec in records:
            tree.insert("", tk.END, values=[rec[col] for col in cols])
        tree.pack(fill=tk.BOTH, expand=True)
        self.stats_window = stats_win
    
    # Hàm thống kê cuộc hội thoại theo giao thức TCP
    def show_tcp_conversation_stats(self):
        if not self.packets:
            messagebox.showwarning("Cảnh báo", "Không có gói tin để thống kê!")
            return
        if not self.capture_start_time:
            self.capture_start_time = min(p.timestamp for p in self.packets)
        conv_dict = {}
        for p in self.packets:
            if not (p.haslayer(TCP) and p.haslayer(IP)):
                continue
            src_ip = p[IP].src
            dst_ip = p[IP].dst
            src_port = p[TCP].sport
            dst_port = p[TCP].dport
            tup1 = (src_ip, src_port)
            tup2 = (dst_ip, dst_port)
            key = tuple(sorted([tup1, tup2]))
            if key not in conv_dict:
                conv_dict[key] = {
                    "packets_total": 0,
                    "bytes_total": 0,
                    "packets_A_to_B": 0,
                    "bytes_A_to_B": 0,
                    "packets_B_to_A": 0,
                    "bytes_B_to_A": 0,
                    "first_timestamp": p.timestamp,
                    "last_timestamp": p.timestamp
                }
            conv = conv_dict[key]
            conv["packets_total"] += 1
            pkt_len = len(p.raw)
            conv["bytes_total"] += pkt_len
            conv["first_timestamp"] = min(conv["first_timestamp"], p.timestamp)
            conv["last_timestamp"] = max(conv["last_timestamp"], p.timestamp)
            # Xác định hướng dựa trên cặp (IP, Port)
            if (src_ip, src_port) == key[0]:
                conv["packets_A_to_B"] += 1
                conv["bytes_A_to_B"] += pkt_len
            else:
                conv["packets_B_to_A"] += 1
                conv["bytes_B_to_A"] += pkt_len
        records = []
        for key, conv in conv_dict.items():
            duration = conv["last_timestamp"] - conv["first_timestamp"]
            rel_start = conv["first_timestamp"] - self.capture_start_time
            bits_A_to_B = (conv["bytes_A_to_B"] * 8 / duration) if duration > 0 else 0
            bits_B_to_A = (conv["bytes_B_to_A"] * 8 / duration) if duration > 0 else 0
            record = {
                "Address A": key[0][0],
                "Address B": key[1][0],
                "Port A": key[0][1],
                "Port B": key[1][1],
                "Packets": conv["packets_total"],
                "Bytes": conv["bytes_total"],
                "Packets A→B": conv["packets_A_to_B"],
                "Bytes A→B": conv["bytes_A_to_B"],
                "Packets B→A": conv["packets_B_to_A"],
                "Bytes B→A": conv["bytes_B_to_A"],
                "Rel Start": f"{rel_start:.3f}",
                "Duration": f"{duration:.3f}",
                "Bits/s A→B": f"{bits_A_to_B:.2f}",
                "Bits/s B→A": f"{bits_B_to_A:.2f}",
                "Flows": 1
            }
            records.append(record)
        stats_win = tk.Toplevel(self.root)
        stats_win.title("Thống kê cuộc hội thoại (TCP)")
        cols = ["Address A", "Address B", "Port A", "Port B", "Packets", "Bytes",
                "Packets A→B", "Bytes A→B", "Packets B→A", "Bytes B→A", 
                "Rel Start", "Duration", "Bits/s A→B", "Bits/s B→A", "Flows"]
        tree = ttk.Treeview(stats_win, columns=cols, show="headings")
        for col in cols:
            tree.heading(col, text=col)
            tree.column(col, width=100)
        for rec in records:
            tree.insert("", tk.END, values=[rec[col] for col in cols])
        tree.pack(fill=tk.BOTH, expand=True)
        self.stats_window = stats_win

    def reset_sniffing(self):
        self.stop_sniffing()
        self.packets.clear()
        self.tree.delete(*self.tree.get_children())
        self.text_area.delete("1.0", tk.END)        
        self.start_button.config(state=tk.NORMAL)
        messagebox.showinfo("Reset", "Sniffer đã được reset thành công!")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
