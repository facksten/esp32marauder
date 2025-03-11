import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import platform
import subprocess
import itertools
import re
import threading

class MarauderTool:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Silent Guardian")
        self.root.geometry("1000x1200")
        self.root.configure(bg="#1e1e1e")
        self.root.resizable(True, True)
        self.root.minsize(900, 1000)
        
        self.aircrack_path = self.get_aircrack_path()
        self.create_gui()

    def get_aircrack_path(self):
        """Get the appropriate path for aircrack-ng based on the operating system"""
        system = platform.system()
        if system == "Windows":
            path = os.path.join(os.getcwd(), "aircrack-ng", "aircrack-ng.exe")
        elif system == "Linux":
            path = "/usr/bin/aircrack-ng"
        else:  # Darwin
            path = "/usr/local/bin/aircrack-ng"
        return path

    def install_aircrack(self):
        """Install aircrack-ng based on the operating system"""
        system = platform.system()
        try:
            if system == "Windows":
                url = "https://download.aircrack-ng.org/aircrack-ng-1.7-win.zip"
                self.download_and_extract(url)
            elif system == "Linux":
                if os.geteuid() == 0:  # Running as root
                    subprocess.run(["apt-get", "update"])
                    subprocess.run(["apt-get", "install", "-y", "aircrack-ng"])
                else:
                    messagebox.showerror("Error", "Please run with sudo privileges to install aircrack-ng")
            else:  # Darwin
                subprocess.run(["brew", "install", "aircrack-ng"])
        except Exception as e:
            messagebox.showerror("Installation Error", f"Failed to install aircrack-ng: {str(e)}")

    def download_and_extract(self, url):
        """Download and extract aircrack-ng for Windows"""
        try:
            response = requests.get(url)
            zip_path = "aircrack-ng.zip"
            with open(zip_path, 'wb') as f:
                f.write(response.content)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall("aircrack-ng")
            
            os.remove(zip_path)
        except Exception as e:
            messagebox.showerror("Download Error", f"Failed to download aircrack-ng: {str(e)}")

    def create_gui(self):
        """Create the main GUI elements"""
        # Logo
        logo_frame = tk.Frame(self.root, bg="#1e1e1e")
        logo_frame.pack(pady=10)
        logo_label = tk.Label(logo_frame, text="🔒Silent Guardian🔒", 
                            font=("Helvetica", 18, "bold"), bg="#1e1e1e", fg="#00FF7F")
        logo_label.pack()

        # File Selection
        self.create_file_selection()

        # Password Generator
        self.create_password_generator()

        # Aircrack Controls
        self.create_aircrack_controls()

    def create_file_selection(self):
        """Create the file selection section"""
        file_frame = tk.LabelFrame(self.root, text="Files", bg="#1e1e1e", fg="#00FF7F")
        file_frame.pack(padx=10, pady=10, fill="x")

        # PCAP File
        pcap_label = tk.Label(file_frame, text="PCAP File:", bg="#1e1e1e", fg="#FFFFFF")
        pcap_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.pcap_path = tk.Entry(file_frame, width=40)
        self.pcap_path.grid(row=0, column=1, padx=5, pady=5)
        pcap_browse = tk.Button(file_frame, text="Browse", 
                              command=lambda: self.browse_file("pcap"))
        pcap_browse.grid(row=0, column=2, padx=5, pady=5)

        # Wordlist File
        wordlist_label = tk.Label(file_frame, text="Password File:", bg="#1e1e1e", fg="#FFFFFF")
        wordlist_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.wordlist_path = tk.Entry(file_frame, width=40)
        self.wordlist_path.grid(row=1, column=1, padx=5, pady=5)
        wordlist_browse = tk.Button(file_frame, text="Browse", 
                                  command=lambda: self.browse_file("txt"))
        wordlist_browse.grid(row=1, column=2, padx=5, pady=5)

    def browse_file(self, file_type):
        """Browse for files and update the corresponding entry"""
        if file_type == "pcap":
            path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
            if path:
                self.pcap_path.delete(0, tk.END)
                self.pcap_path.insert(0, path)
            return path
        elif file_type == "txt":
            path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
            if path:
                self.wordlist_path.delete(0, tk.END)
                self.wordlist_path.insert(0, path)
            return path

    def create_password_generator(self):
        generator_frame = tk.LabelFrame(self.root, text="Password List Generator", bg="#1e1e1e", fg="#00FF7F")
        generator_frame.pack(padx=10, pady=10, fill="x")

        # ایجاد فریم‌ها برای سازماندهی بهتر فیلدها
        frame1 = tk.Frame(generator_frame, bg="#1e1e1e")
        frame2 = tk.Frame(generator_frame, bg="#1e1e1e")
        frame3 = tk.Frame(generator_frame, bg="#1e1e1e")
        frame4 = tk.Frame(generator_frame, bg="#1e1e1e")

        frames = [frame1, frame2, frame3, frame4]
        for frame in frames:
            frame.pack(fill="x", padx=5, pady=5)

        # فیلدهای ردیف اول
        fields1 = [("SSID", "SSID of the network"), 
                ("Owner Name", "Name of the owner"),
                ("Last Name", "Last name")]

        # فیلدهای ردیف دوم
        fields2 = [("Family Member", "Name of family member"),
                ("Company", "Company name"),
                ("National ID", "National ID number")]

        # فیلدهای ردیف سوم
        fields3 = [("Country", "Country name"),
                ("Phone", "Phone number"),
                ("Gmail", "Gmail address")]

        # فیلدهای ردیف چهارم
        fields4 = [("Birth Year", "Year of birth"),
                ("Current Year", "Current year"),
                ("Custom", "Custom text")]

        fields_in_frames = [(frame1, fields1), (frame2, fields2), 
                        (frame3, fields3), (frame4, fields4)]

        self.generator_entries = {}
        
        for frame, fields in fields_in_frames:
            for i, (field, placeholder) in enumerate(fields):
                tk.Label(frame, text=f"{field}:", bg="#1e1e1e", fg="#FFFFFF").grid(
                    row=0, column=i*3, padx=5, pady=2)
                entry = tk.Entry(frame, width=20)
                entry.insert(0, placeholder)
                entry.config(fg='gray')
                entry.grid(row=0, column=i*3+1, padx=5, pady=2)
                self.generator_entries[field] = entry
                
                entry.bind('<FocusIn>', lambda e, entry=entry, ph=placeholder: 
                        self.on_entry_focus_in(e, entry, ph))
                entry.bind('<FocusOut>', lambda e, entry=entry, ph=placeholder: 
                        self.on_entry_focus_out(e, entry, ph))

                # اضافه کردن بررسی کد ملی برای فیلد کد ملی
                if field == "National ID":
                    check_button = tk.Button(frame, text="Check", 
                                           command=lambda e=entry: self.check_national_id(e))
                    check_button.grid(row=0, column=i*3+2, padx=5, pady=2)
                    self.national_id_status = tk.Label(frame, text="", bg="#1e1e1e", fg="#FF0000")
                    self.national_id_status.grid(row=0, column=i*3+3, padx=5, pady=2)

        # اضافه کردن چک باکس‌ها و دکمه‌ها
        self.use_symbols = tk.BooleanVar(value=True)
        self.use_numbers = tk.BooleanVar(value=True)
        self.use_uppercase = tk.BooleanVar(value=True)
        self.use_lowercase = tk.BooleanVar(value=True)

        symbols_check = tk.Checkbutton(generator_frame, text="Include Special Symbols (@#$._)", 
                                    variable=self.use_symbols, bg="#1e1e1e", fg="#FFFFFF",
                                    selectcolor="#1e1e1e")
        symbols_check.pack(pady=5)

        numbers_check = tk.Checkbutton(generator_frame, text="Include Numbers (123)", 
                                    variable=self.use_numbers, bg="#1e1e1e", fg="#FFFFFF",
                                    selectcolor="#1e1e1e")
        numbers_check.pack(pady=5)

        uppercase_check = tk.Checkbutton(generator_frame, text="Include Uppercase Letters", 
                                    variable=self.use_uppercase, bg="#1e1e1e", fg="#FFFFFF",
                                    selectcolor="#1e1e1e")
        uppercase_check.pack(pady=5)

        lowercase_check = tk.Checkbutton(generator_frame, text="Include Lowercase Letters", 
                                    variable=self.use_lowercase, bg="#1e1e1e", fg="#FFFFFF",
                                    selectcolor="#1e1e1e")
        lowercase_check.pack(pady=5)

        generate_btn = tk.Button(generator_frame, text="Generate Password List", 
                            command=self.generate_password_list)
        generate_btn.pack(pady=5)

    def check_national_id(self, entry):
        """Check if the national ID is valid and update the status label"""
        national_id = entry.get()
        if self.check_code_meli(national_id):
            self.national_id_status.config(text="✅", fg="#00FF00")
        else:
            self.national_id_status.config(text="❌", fg="#FF0000")

    def check_code_meli(self, code):
        """
        بررسی صحت کد ملی ایران
        :param code: کد ملی به صورت رشته
        :return: True اگر کد ملی معتبر باشد، در غیر این صورت False
        """
        if len(code) < 8 or int(code) == 0:
            return False
        
        code = ('0000' + code)[-10:]  # اضافه کردن صفر به ابتدا تا طول کد 10 رقم شود
        if int(code[3:6]) == 0:
            return False
        
        c = int(code[9])
        s = sum(int(code[i]) * (10 - i) for i in range(9))
        s %= 11
        
        return (s < 2 and c == s) or (s >= 2 and c == (11 - s))

    def on_entry_focus_in(self, event, entry, placeholder):
        """Handle entry field focus in"""
        if entry.get() == placeholder:
            entry.delete(0, tk.END)
            entry.config(fg='black')

    def on_entry_focus_out(self, event, entry, placeholder):
        """Handle entry field focus out"""
        if entry.get() == "":
            entry.insert(0, placeholder)
            entry.config(fg='gray')

    def generate_password_list(self):
        # جمع‌آوری مقادیر غیر خالی
        values = []
        for field, entry in self.generator_entries.items():
            value = entry.get()
            if value and value not in ["SSID of the network", "Name of the owner", "Last name", 
                                    "Name of family member", "Company name", 
                                    "National ID number", "Country name", "Phone number", 
                                    "Gmail address", "Year of birth", "Current year", 
                                    "Custom text to include"]:
                values.append(value)
                if self.use_uppercase.get():
                    values.append(value.upper())
                if self.use_lowercase.get():
                    values.append(value.lower())
                if self.use_numbers.get():
                    values.append(value + "123")
                    values.append(value + "1234")

        if not values:
            messagebox.showwarning("Warning", "Please enter at least one value")
            return

        symbols = ['@', '#', '$', '.', '_', '!'] if self.use_symbols.get() else []
        generated_passwords = set()

        # ترکیب مقادیر با طول‌های مختلف
        for length in range(1, 5):
            for combo in itertools.combinations(values, length):
                password = ''.join(combo)
                if 8 <= len(password) <= 16:
                    generated_passwords.add(password)
                    # اضافه کردن ترکیب با سمبل‌ها
                    for symbol in symbols:
                        generated_passwords.add(password + symbol)
                        generated_passwords.add(symbol + password)

        # ترکیب permutation برای تنوع بیشتر
        for length in range(2, 4):
            for combo in itertools.permutations(values, length):
                password = ''.join(combo)
                if 8 <= len(password) <= 16:
                    generated_passwords.add(password)

        try:
            with open("generated_passwords.txt", "w", encoding='utf-8') as f:
                for password in generated_passwords:
                    f.write(password + "\n")

            self.wordlist_path.delete(0, tk.END)
            self.wordlist_path.insert(0, os.path.abspath("generated_passwords.txt"))
            messagebox.showinfo("Success", f"Password list generated with {len(generated_passwords)} combinations!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save password list: {str(e)}")

    def create_aircrack_controls(self):
        """Create the aircrack-ng controls section"""
        aircrack_frame = tk.LabelFrame(self.root, text="Aircrack-ng", bg="#1e1e1e", fg="#00FF7F")
        aircrack_frame.pack(padx=10, pady=10, fill="x")

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(aircrack_frame, length=300, mode='indeterminate',
                                        variable=self.progress_var)
        self.progress_bar.pack(pady=5)
        
        # Status label
        self.status_label = tk.Label(aircrack_frame, text="", bg="#1e1e1e", fg="#00FF7F")
        self.status_label.pack(pady=5)

        # Password display
        password_frame = tk.Frame(aircrack_frame, bg="#1e1e1e")
        password_frame.pack(pady=5, fill="x")
        
        self.password_label = tk.Label(password_frame, text="Found Password:", 
                                    bg="#1e1e1e", fg="#00FF7F")
        self.password_label.pack(side="left", padx=5)
        
        self.password_display = tk.Entry(password_frame, width=20, 
                                    bg="#2e2e2e", fg="#00FF7F", 
                                    readonlybackground="#2e2e2e")
        self.password_display.pack(side="left", padx=5)
        self.password_display.configure(state='readonly')

        self.save_logs = tk.BooleanVar()
        save_logs_check = tk.Checkbutton(aircrack_frame, text="Save Logs", 
                                        variable=self.save_logs, 
                                        bg="#1e1e1e", fg="#FFFFFF",
                                        selectcolor="#1e1e1e",
                                        activebackground="#1e1e1e",
                                        activeforeground="#FFFFFF")
        save_logs_check.pack(pady=5)

        aircrack_btn = tk.Button(aircrack_frame, text="Start Aircrack-ng", 
                                command=self.start_aircrack_thread)
        aircrack_btn.pack(pady=5)

    def start_aircrack_thread(self):
        """Start aircrack in a separate thread"""
        self.progress_bar.start(10)
        self.status_label.config(text="Cracking in progress...")
        self.password_display.configure(state='normal')
        self.password_display.delete(0, tk.END)
        self.password_display.configure(state='readonly')
        
        thread = threading.Thread(target=self.run_aircrack)
        thread.daemon = True
        thread.start()

    def extract_password(self, output):
        """Extract password from aircrack output"""
        match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", output)
        if match:
            return match.group(1)
        return None

    def run_aircrack(self):
        """Run aircrack-ng with progress indication"""
        pcap_file = self.pcap_path.get()
        wordlist_file = self.wordlist_path.get()

        if not os.path.isfile(pcap_file) or not os.path.isfile(wordlist_file):
            self.root.after(0, lambda: messagebox.showerror("Error", "Invalid PCAP or wordlist file path."))
            self.stop_progress()
            return

        if not os.path.exists(self.aircrack_path):
            response = messagebox.askyesno("Error", 
                "aircrack-ng is not installed. Would you like to install it now?")
            if response:
                self.install_aircrack()
            self.stop_progress()
            return

        command = [self.aircrack_path, "-w", wordlist_file, pcap_file]
        try:
            result = subprocess.run(command, capture_output=True, text=True)
            output = result.stdout

            if self.save_logs.get():
                with open("aircrack_logs.txt", "w") as log_file:
                    log_file.write(output)

            # Extract and display password if found
            password = self.extract_password(output)
            if password:
                self.root.after(0, lambda: self.show_success(password))
            else:
                self.root.after(0, lambda: self.show_failure())

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to run aircrack-ng: {str(e)}"))
        finally:
            self.stop_progress()

    def show_success(self, password):
        """Show success message and display password"""
        self.status_label.config(text="Password Found!")
        self.password_display.configure(state='normal')
        self.password_display.delete(0, tk.END)
        self.password_display.insert(0, password)
        self.password_display.configure(state='readonly')
        messagebox.showinfo("Success", f"Password found: {password}")

    def show_failure(self):
        """Show failure message"""
        self.status_label.config(text="Password not found")
        messagebox.showinfo("Result", "Password not found.")

    def stop_progress(self):
        """Stop progress bar animation"""
        self.progress_bar.stop()
        self.status_label.config(text="")

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = MarauderTool()
    app.run()