import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import serial
import serial.tools.list_ports
import threading
import time
import os
import re
import folium
from folium.plugins import MarkerCluster
import webbrowser

VERSION = "1.5.5"

class MarauderCommander:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"Silent Guardian v{VERSION}")
        self.root.geometry("1200x900")
        self.root.configure(bg="#1e1e1e")

        # ایجاد Canvas و Scrollbar
        self.canvas = tk.Canvas(self.root, bg="#1e1e1e")
        self.scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg="#1e1e1e")

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            )
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        self.serial_port = None
        self.is_connected = False
        self.ap_list = []
        self.scanning = False  # متغیر جدید برای پیگیری وضعیت اسکن

        self.create_gui()

    def create_gui(self):
        # تمام المان‌ها به جای self.root به self.scrollable_frame اضافه می‌شوند
        logo_frame = tk.Frame(self.scrollable_frame, bg="#1e1e1e")
        logo_frame.pack(pady=10, fill="x")
        logo_label = tk.Label(logo_frame, text="🔒Silent Guardian🔒", 
                              font=("Helvetica", 18, "bold"), bg="#1e1e1e", fg="#00FF7F")
        logo_label.pack()

        self.create_serial_frame()
        self.create_output_frame()
        self.create_network_list_frame()
        self.create_command_frames()
        self.create_sniffing_command_frame()

        # اضافه کردن دکمه نمایش نقشه وای‌فای
        map_button = tk.Button(self.scrollable_frame, text="Show WiFi Map", command=self.show_wifi_map,
                               bg="#2e2e2e", fg="#FFFFFF")
        map_button.pack(pady=10)

        # اضافه کردن دکمه Wardrive
        wardrive_button = tk.Button(self.scrollable_frame, text="Wardrive", command=self.start_wardrive,
                                    bg="#2e2e2e", fg="#FFFFFF")
        wardrive_button.pack(pady=10)

    def create_serial_frame(self):
        serial_frame = tk.LabelFrame(self.scrollable_frame, text="Serial Monitor", bg="#1e1e1e", fg="#00FF7F")
        serial_frame.pack(fill="x", padx=10, pady=5)

        port_frame = tk.Frame(serial_frame, bg="#1e1e1e")
        port_frame.pack(fill="x", padx=5, pady=5)

        self.port_var = tk.StringVar(value="Select COM Port")
        self.port_menu = tk.OptionMenu(port_frame, self.port_var, "")
        self.port_menu.config(width=30, bg="#2e2e2e", fg="#FFFFFF")
        self.port_menu.pack(side="left", padx=5)

        refresh_btn = tk.Button(port_frame, text="Refresh", command=self.refresh_ports,
                               bg="#2e2e2e", fg="#FFFFFF")
        refresh_btn.pack(side="left", padx=5)

        self.connect_btn = tk.Button(port_frame, text="Connect", command=self.toggle_connection,
                                    bg="#2e2e2e", fg="#FFFFFF")
        self.connect_btn.pack(side="left", padx=5)

        self.refresh_ports()

    def create_output_frame(self):
        output_frame = tk.LabelFrame(self.root, text="Command Output", bg="#1e1e1e", fg="#00FF7F")
        output_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, height=10,
                                                   bg="#2e2e2e", fg="#FFFFFF")
        self.output_text.pack(fill="both", expand=True, padx=5, pady=5)

    def create_network_list_frame(self):
        self.networks_frame = tk.LabelFrame(self.root, text="WiFi Networks", bg="#1e1e1e", fg="#00FF7F")
        self.networks_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        columns = ("index", "rssi", "channel", "bssid", "essid")
        self.networks_tree = ttk.Treeview(self.networks_frame, columns=columns, show="headings")
        
        self.networks_tree.heading("index", text="#")
        self.networks_tree.heading("rssi", text="RSSI")
        self.networks_tree.heading("channel", text="CH")
        self.networks_tree.heading("bssid", text="BSSID")
        self.networks_tree.heading("essid", text="ESSID")
        
        self.networks_tree.column("index", width=40)
        self.networks_tree.column("rssi", width=60)
        self.networks_tree.column("channel", width=60)
        self.networks_tree.column("bssid", width=150)
        self.networks_tree.column("essid", width=200)
        
        scrollbar = ttk.Scrollbar(self.networks_frame, orient="vertical", command=self.networks_tree.yview)
        self.networks_tree.configure(yscrollcommand=scrollbar.set)
        
        self.networks_tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        scrollbar.pack(side="right", fill="y", pady=5)
        
        actions_frame = tk.Frame(self.networks_frame, bg="#1e1e1e")
        actions_frame.pack(fill="x", padx=5, pady=5)
        
        select_btn = tk.Button(actions_frame, text="Select AP", command=self.select_ap,
                            bg="#2e2e2e", fg="#FFFFFF")
        select_btn.pack(side="left", padx=5)
        
        select_all_btn = tk.Button(actions_frame, text="Select All", command=self.select_all_aps,
                                bg="#2e2e2e", fg="#FFFFFF")
        select_all_btn.pack(side="left", padx=5)
        
        attack_label = tk.Label(actions_frame, text="Attack:", bg="#1e1e1e", fg="#00FF7F")
        attack_label.pack(side="left", padx=(20, 5))
        
        attack_types = [
            ("Deauth", "deauth"),
            ("Beacon", "beacon"),
            ("Probe", "probe"),
            ("RickRoll", "rickroll")
        ]
        
        for text, cmd in attack_types:
            btn = tk.Button(actions_frame, text=text,
                          command=lambda c=cmd: self.attack_selected(c),
                          bg="#2e2e2e", fg="#FFFFFF")
            btn.pack(side="left", padx=5)

    def create_command_frames(self):
        commands_frame = tk.LabelFrame(self.root, text="Commands", bg="#1e1e1e", fg="#00FF7F")
        commands_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        scan_frame = tk.LabelFrame(commands_frame, text="Scan", bg="#1e1e1e", fg="#00FF7F")
        scan_frame.pack(fill="x", padx=5, pady=5)
        
        scan_buttons = [
            ("Scan AP", "scanap"),
            ("Stop Scan", "stopscan"),
            ("Show List", "list"),
            ("Clear List", "clearlist")
        ]
        
        for text, cmd in scan_buttons:
            btn = tk.Button(scan_frame, text=text,
                          command=lambda c=cmd: self.send_command(c),
                          bg="#2e2e2e", fg="#FFFFFF")
            btn.pack(side="left", padx=5)
        
        attack_frame = tk.LabelFrame(commands_frame, text="Attack", bg="#1e1e1e", fg="#00FF7F")
        attack_frame.pack(fill="x", padx=5, pady=5)
        
        beacon_frame = tk.Frame(attack_frame, bg="#1e1e1e")
        beacon_frame.pack(fill="x", pady=5)
        
        beacon_buttons = [
            ("Beacon List", "attack -t beacon -l"),
            ("Beacon Random", "attack -t beacon -r"),
            ("Beacon AP", "attack -t beacon -a")
        ]
        
        for text, cmd in beacon_buttons:
            btn = tk.Button(beacon_frame, text=text,
                          command=lambda c=cmd: self.send_command(c),
                          bg="#2e2e2e", fg="#FFFFFF")
            btn.pack(side="left", padx=5)
        
        ble_frame = tk.LabelFrame(commands_frame, text="BLE", bg="#1e1e1e", fg="#00FF7F")
        ble_frame.pack(fill="x", padx=5, pady=5)
        
        ble_buttons = [
            ("Spam All", "blespam -t all"),
            ("Spam Samsung", "blespam -t samsung"),
            ("Spam Windows", "blespam -t windows"),
            ("Spam Apple", "blespam -t apple")
        ]
        
        for text, cmd in ble_buttons:
            btn = tk.Button(ble_frame, text=text,
                          command=lambda c=cmd: self.send_command(c),
                          bg="#2e2e2e", fg="#FFFFFF")
            btn.pack(side="left", padx=5)
        
        terminal_frame = tk.LabelFrame(commands_frame, text="Custom Terminal", bg="#1e1e1e", fg="#00FF7F")
        terminal_frame.pack(fill="x", padx=5, pady=5)

        self.terminal_entry = tk.Entry(terminal_frame, width=50, 
                                    bg="#2e2e2e", fg="#FFFFFF", 
                                    insertbackground="#FFFFFF")
        self.terminal_entry.pack(side="left", padx=5, expand=True, fill="x")

        terminal_send_btn = tk.Button(terminal_frame, text="Send", 
                                   command=self.send_terminal_command,
                                   bg="#2e2e2e", fg="#FFFFFF")
        terminal_send_btn.pack(side="left", padx=5)
        
        stop_frame = tk.Frame(commands_frame, bg="#1e1e1e")
        stop_frame.pack(pady=10)

        tk.Button(stop_frame, text="STOP", 
                  command=lambda: self.send_command("stopscan"),
                  bg="#FF4444", fg="#FFFFFF",
                  font=("Helvetica", 12, "bold")).pack(side="left", padx=5)

        tk.Button(stop_frame, text="REBOOT", 
                  command=lambda: self.send_command("reboot"),
                  bg="#FFA500", fg="#000000",
                  font=("Helvetica", 12, "bold")).pack(side="left", padx=5)

        whole_jam_btn = tk.Button(commands_frame, text="WHOLE JAM", 
                                   command=self.whole_jam_sequence,
                                   bg="#800080", fg="#FFFFFF", 
                                   font=("Helvetica", 12, "bold"))
        whole_jam_btn.pack(pady=10)

    def create_sniffing_command_frame(self):
        sniffing_frame = tk.LabelFrame(self.root, text="Sniffing Commands", bg="#1e1e1e", fg="#00FF7F")
        sniffing_frame.pack(fill="x", padx=10, pady=5)
        
        sniffing_commands = [
            ("Sig Mon", "sigmon"),
            ("Scan AP", "scanap"),
            ("Scan STA", "scansta"),
            ("Sniff Raw", "sniffraw"),
            ("Sniff Beacon", "sniffbeacon"),
            ("Sniff Probe", "sniffprobe"),
            ("Sniff PWN", "sniffpwn"),
            ("Sniff ESP", "sniffesp"),
            ("Sniff Deauth", "sniffdeauth"),
            ("Sniff Skim", "sniffskim"),
            ("Sniff PMKID", "sniffpmkid")
        ]
        
        for text, cmd in sniffing_commands:
            btn = tk.Button(sniffing_frame, text=text,
                          command=lambda c=cmd: self.send_command(c),
                          bg="#2e2e2e", fg="#FFFFFF")
            btn.pack(side="left", padx=5)

    def whole_jam_sequence(self):
        if not self.is_connected:
            messagebox.showerror("Error", "Please connect to a device first")
            return
        
        self.send_command("scanap")
        self.write_to_output("Starting Whole Jam Sequence...\n")
        
        self.root.after(20000, self.whole_jam_step5)

    def whole_jam_step5(self):
        self.send_command("stopscan")
        self.root.after(1000, self.whole_jam_step2)

    def whole_jam_step2(self):
        self.send_command("select -a all")
        
        self.root.after(1000, self.whole_jam_step3)

    def whole_jam_step3(self):
        self.send_command("attack -t deauth")
        self.write_to_output("Whole Jam Sequence Completed!\n")

    def refresh_ports(self):
        ports = []
        if os.name == 'posix':
            for i in range(4):
                port = f'/dev/ttyUSB{i}'
                if os.path.exists(port):
                    ports.append(port)
            for i in range(4):
                port = f'/dev/ttyACM{i}'
                if os.path.exists(port):
                    ports.append(port)
        else:
            ports = [p.device for p in serial.tools.list_ports.comports()]

        menu = self.port_menu["menu"]
        menu.delete(0, "end")
        
        if not ports:
            menu.add_command(label="No ports found",
                           command=lambda: self.port_var.set("No ports found"))
            self.port_var.set("No ports found")
        else:
            for port in ports:
                menu.add_command(label=port,
                               command=lambda p=port: self.port_var.set(p))

    def toggle_connection(self):
        if not self.is_connected:
            try:
                port = self.port_var.get()
                if port == "Select COM Port" or port == "No ports found":
                    messagebox.showerror("Error", "Please select a COM port")
                    return
                
                self.serial_port = serial.Serial(port, 115200, timeout=1)
                self.is_connected = True
                self.connect_btn.configure(text="Disconnect")
                
                # شروع خواندن داده‌های سریال
                self.read_serial()
                
                self.write_to_output(f"Connected to {port}\n")
            except Exception as e:
                messagebox.showerror("Connection Error", str(e))
        else:
            if self.serial_port:
                self.serial_port.close()
            self.is_connected = False
            self.connect_btn.configure(text="Connect")
            self.write_to_output("Disconnected\n")

    def send_command(self, command):
        if not self.is_connected:
            messagebox.showerror("Error", "Please connect to a device first")
            return
            
        try:
            # تغییر وضعیت اسکن براساس دستور
            if command == "scanap":
                self.scanning = True
                # پاک کردن لیست قبلی هنگام شروع اسکن جدید
                self.ap_list = []
                for item in self.networks_tree.get_children():
                    self.networks_tree.delete(item)
            
            elif command == "stopscan":
                if self.scanning:
                    # وقتی اسکن متوقف می‌شود، پیام نتایج نمایش داده می‌شود
                    self.root.after(500, self.show_scan_results)  # تاخیر کوتاه برای دریافت آخرین داده‌ها
                self.scanning = False
            
            self.serial_port.write(f"{command}\n".encode())
            self.write_to_output(f"Sent: {command}\n")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send command: {str(e)}")

    def show_scan_results(self):
        # نمایش نتایج اسکن بعد از توقف
        if len(self.ap_list) > 0:
            messagebox.showinfo("Scan Results", f"Found {len(self.ap_list)} networks")
        else:
            messagebox.showinfo("Scan Results", "No networks found")

    def send_terminal_command(self):
        command = self.terminal_entry.get().strip()
        
        if not self.is_connected:
            messagebox.showerror("Error", "Please connect to a device first")
            return
        
        try:
            # بررسی دستورات scanap و stopscan
            if command == "scanap":
                self.scanning = True
                # پاک کردن لیست قبلی هنگام شروع اسکن جدید
                self.ap_list = []
                for item in self.networks_tree.get_children():
                    self.networks_tree.delete(item)
            elif command == "stopscan":
                if self.scanning:
                    # وقتی اسکن متوقف می‌شود، پیام نتایج نمایش داده می‌شود
                    self.root.after(500, self.show_scan_results)
                self.scanning = False
                
            self.serial_port.write(f"{command}\n".encode())
            self.write_to_output(f"Terminal Sent: {command}\n")
            
            self.terminal_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send command: {str(e)}")

    def read_serial(self):
        try:
            if self.serial_port and self.serial_port.in_waiting:
                data = self.serial_port.readline().decode(errors='replace').strip()
                self.root.after(0, self.process_output, data)
        except Exception as e:
            self.root.after(0, self.disconnect_on_error, str(e))
        
        if self.is_connected:
            self.root.after(100, self.read_serial)

    def process_output(self, data):
        self.write_to_output(f"{data}\n")
        
        if "RSSI:" in data:
            ap_pattern = r"RSSI: ([-\d]+) Ch: (\d+) BSSID: ([0-9a-f:]+) ESSID: (.+)"
            beacon_pattern = r"Beacon: .+ (\d+) \d+"
            
            ap_match = re.search(ap_pattern, data)
            beacon_index = None
            
            if "Beacon:" in data:
                beacon_match = re.search(beacon_pattern, data)
                if beacon_match:
                    beacon_index = beacon_match.group(1)
            
            if ap_match:
                rssi = ap_match.group(1)
                channel = ap_match.group(2)
                bssid = ap_match.group(3)
                essid = ap_match.group(4)
                
                # بررسی تکراری نبودن MAC آدرس
                if not any(ap['bssid'] == bssid for ap in self.ap_list):
                    index = len(self.ap_list) + 1
                    self.ap_list.append({
                        'index': index,
                        'rssi': rssi,
                        'channel': channel,
                        'bssid': bssid,
                        'essid': essid,
                        'lat': None,  # مختصات GPS
                        'lon': None   # مختصات GPS
                    })
                    
                    self.networks_tree.insert("", tk.END, values=(index, rssi, channel, bssid, essid))
        
        elif "|" in data:  # پردازش خروجی wardrive
            # الگوی جدید برای تطبیق با خروجی واقعی
            wardrive_pattern = r"(\d+) \| ([0-9a-fA-F:]+),([^,]+),\[([^\]]+)\],([^,]+),(\d+),([-\d]+),([\d.]+),([\d.]+),([\d.]+),([\d.]+),(\w+)"
            wardrive_match = re.search(wardrive_pattern, data)
            
            if wardrive_match:
                index = int(wardrive_match.group(1))
                bssid = wardrive_match.group(2)
                essid = wardrive_match.group(3)
                encryption = wardrive_match.group(4)
                date_time = wardrive_match.group(5)  # تاریخ و زمان
                channel = int(wardrive_match.group(6))
                rssi = int(wardrive_match.group(7))
                lat = float(wardrive_match.group(8))  # عرض جغرافیایی
                lon = float(wardrive_match.group(9))  # طول جغرافیایی
                altitude = float(wardrive_match.group(10))  # ارتفاع
                accuracy = float(wardrive_match.group(11))  # دقت
                
                # بررسی تکراری نبودن MAC آدرس
                if not any(ap['bssid'] == bssid for ap in self.ap_list):
                    # اضافه کردن به لیست ap_list با مختصات GPS
                    self.ap_list.append({
                        'index': index,
                        'rssi': rssi,
                        'channel': channel,
                        'bssid': bssid,
                        'essid': essid,
                        'encryption': encryption,
                        'lat': lat,
                        'lon': lon,
                        'altitude': altitude,
                        'accuracy': accuracy,
                        'date_time': date_time
                    })
                    
                    # نمایش در Treeview
                    self.networks_tree.insert("", tk.END, values=(index, rssi, channel, bssid, essid))

    def disconnect_on_error(self, error):
        messagebox.showerror("Serial Error", error)
        self.toggle_connection()

    def write_to_output(self, message):
        self.output_text.insert(tk.END, message)
        self.output_text.see(tk.END)

    def select_ap(self):
        selected_items = self.networks_tree.selection()
        if not selected_items:
            messagebox.showwarning("Selection", "Please select at least one AP from the list")
            return
        
        indices = []
        for item in selected_items:
            item_values = self.networks_tree.item(item, "values")
            indices.append(item_values[0])
        
        indices_str = ",".join(indices)
        command = f"select -a {indices_str}"
        self.send_command(command)
        
        messagebox.showinfo("Selection", f"Selected APs: {indices_str}")

    def select_all_aps(self):
        if not self.ap_list:
            messagebox.showwarning("Selection", "No APs in the list")
            return
        
        command = "select -a all"
        self.send_command(command)
        
        messagebox.showinfo("Selection", "Selected all APs")

    def attack_selected(self, attack_type):
        command = f"attack -t {attack_type}"
        self.send_command(command)

    def show_wifi_map(self):
        if not self.ap_list:
            messagebox.showwarning("No Data", "No WiFi networks found to display on the map.")
            return

        # بررسی وجود مختصات GPS در حداقل یکی از شبکه‌ها
        has_coordinates = any(ap.get('lat') is not None and ap.get('lon') is not None for ap in self.ap_list)
        
        if not has_coordinates:
            messagebox.showwarning("No GPS Data", "No GPS coordinates found. Run 'wardrive' to collect location data.")
            return

        # محاسبه مرکز نقشه (میانگین مختصات موجود)
        valid_coords = [(ap['lat'], ap['lon']) for ap in self.ap_list if ap.get('lat') is not None and ap.get('lon') is not None]
        if valid_coords:
            avg_lat = sum(lat for lat, _ in valid_coords) / len(valid_coords)
            avg_lon = sum(lon for _, lon in valid_coords) / len(valid_coords)
            map_center = [avg_lat, avg_lon]
        else:
            map_center = [35.6895, 51.3890]  # مختصات پیش‌فرض
        
        # ایجاد نقشه با مختصات مرکزی
        wifi_map = folium.Map(location=map_center, zoom_start=15)

        # ایجاد خوشه‌بندی برای مارکرها
        marker_cluster = MarkerCluster().add_to(wifi_map)

        # اضافه کردن مارکرها برای هر وای‌فای
        for ap in self.ap_list:
            bssid = ap['bssid']
            essid = ap['essid']
            rssi = ap.get('rssi', 0)
            channel = ap.get('channel', '?')
            
            # استفاده از مختصات GPS اگر موجود باشد
            if ap.get('lat') is not None and ap.get('lon') is not None:
                lat = ap['lat']
                lon = ap['lon']
                
                # اطلاعات اضافی از wardrive
                encryption = ap.get('encryption', 'Unknown')
                date_time = ap.get('date_time', 'Unknown')
                altitude = ap.get('altitude', 'Unknown')
                accuracy = ap.get('accuracy', 'Unknown')

                # انتخاب رنگ براساس قدرت سیگنال
                try:
                    rssi_val = int(rssi)
                    if rssi_val > -65:
                        color = 'green'
                    elif rssi_val > -80:
                        color = 'orange'
                    else:
                        color = 'red'
                except (ValueError, TypeError):
                    color = 'blue'  # رنگ پیش‌فرض

                # ایجاد پاپ‌آپ برای نمایش اطلاعات وای‌فای
                popup_text = f"""
                <b>ESSID:</b> {essid}<br>
                <b>BSSID:</b> {bssid}<br>
                <b>RSSI:</b> {rssi} dBm<br>
                <b>Channel:</b> {channel}<br>
                <b>Encryption:</b> {encryption}<br>
                <b>Date/Time:</b> {date_time}<br>
                <b>Latitude:</b> {lat}<br>
                <b>Longitude:</b> {lon}<br>
                <b>Altitude:</b> {altitude} m<br>
                <b>GPS Accuracy:</b> {accuracy} m
                """
                folium.Marker(
                    [lat, lon], 
                    popup=folium.Popup(popup_text, max_width=300),
                    icon=folium.Icon(color=color, icon='wifi', prefix='fa')
                ).add_to(marker_cluster)

        # ذخیره نقشه به عنوان یک فایل HTML
        try:
            wifi_map.save("wifi_map.html")
            webbrowser.open("wifi_map.html")
            messagebox.showinfo("Map Created", "WiFi map has been created and opened in your browser.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create map: {str(e)}")

    def start_wardrive(self):
        if not self.is_connected:
            messagebox.showerror("Error", "Please connect to a device first")
            return
        
        self.send_command("wardrive")
        self.write_to_output("Starting Wardrive...\n")

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = MarauderCommander()
    app.run()