import tkinter as tk
from tkinter import scrolledtext, messagebox
import serial
import serial.tools.list_ports
import threading
import time
import os

VERSION = "1.5.2"  # نسخه جدید
class MarauderCommander:
   def __init__(self):
       # می‌توانید نسخه را در عنوان پنجره نیز نمایش دهید
       self.root = tk.Tk()
       self.root.title(f"Silent Guardian v{VERSION}")
       self.root.geometry("1200x900")
       self.root.configure(bg="#1e1e1e")
       
       self.serial_port = None
       self.is_connected = False
       
       self.create_gui()
       
   def create_gui(self):
       # Logo
       logo_frame = tk.Frame(self.root, bg="#1e1e1e")
       logo_frame.pack(pady=10)
       logo_label = tk.Label(logo_frame, text="🔒Silent Guardian🔒", 
                         font=("Helvetica", 18, "bold"), bg="#1e1e1e", fg="#00FF7F")
       logo_label.pack()
       
       self.create_serial_frame()
       
       self.create_output_frame()
       
       self.create_command_frames()
       
       self.create_sniffing_command_frame()
       
   def create_serial_frame(self):
       serial_frame = tk.LabelFrame(self.root, text="Serial Monitor", bg="#1e1e1e", fg="#00FF7F")
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
           ("Sniff Skim", "sniffskim")
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
               
               # شروع خواندن سریال
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
           self.serial_port.write(f"{command}\n".encode())
           self.write_to_output(f"Sent: {command}\n")
       except Exception as e:
           messagebox.showerror("Error", f"Failed to send command: {str(e)}")

   def send_terminal_command(self):
       command = self.terminal_entry.get().strip()
       
       if not self.is_connected:
           messagebox.showerror("Error", "Please connect to a device first")
           return
       
       try:
           self.serial_port.write(f"{command}\n".encode())
           self.write_to_output(f"Terminal Sent: {command}\n")
           
           self.terminal_entry.delete(0, tk.END)
       except Exception as e:
           messagebox.showerror("Error", f"Failed to send command: {str(e)}")

   def read_serial(self):
       try:
           if self.serial_port.in_waiting:
               data = self.serial_port.readline().decode().strip()
               # استفاده از after برای به‌روزرسانی رابط کاربری در main thread
               self.root.after(0, self.write_to_output, f"{data}\n")
       except Exception as e:
           # اگر خطایی رخ داد، اتصال را قطع کنید
           self.root.after(0, self.disconnect_on_error, str(e))
       
       # اگر متصل هستید، بررسی مجدد در 100 میلی‌ثانیه بعد
       if self.is_connected:
           self.root.after(100, self.read_serial)

   def disconnect_on_error(self, error):
       messagebox.showerror("Serial Error", error)
       self.toggle_connection()  # این تابع اتصال را قطع می‌کند

   def write_to_output(self, message):
       self.output_text.insert(tk.END, message)
       self.output_text.see(tk.END)

   def run(self):
       self.root.mainloop()

if __name__ == "__main__":
   app = MarauderCommander()
   app.run()
