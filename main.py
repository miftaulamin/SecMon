"""
Enhanced Security Monitoring Application
Modern GUI with improved design and user experience
"""

import os
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import smtplib
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from email.mime.multipart import MIMEMultipart
from zipfile import ZipFile
import pyautogui
import requests
import json

# --------------------- CONFIG --------------------
SENDER_EMAIL = "Sender email"
SENDER_PASSWORD = "Your Google app password"
VT_API_KEY = "Your Virus Total API key"
RECIPIENT_EMAIL = "Reciever email"

APP_DIR = os.path.join(os.getcwd(), "monitor_data")
SCREEN_DIR = os.path.join(APP_DIR, "screenshots")
os.makedirs(SCREEN_DIR, exist_ok=True)
BLACKLIST_FILE = os.path.join(APP_DIR, "blacklist.txt")
SOFT_LIST_FILE = os.path.join(APP_DIR, "soft_names.txt")

# Default settings
DEFAULT_SCREEN_INTERVAL_MIN = 60
DEFAULT_DAILY_SCAN_HOUR = 12
DEFAULT_WORK_HOURS = 8

# Modern color scheme
COLORS = {
    'primary': '#2563eb',      # Blue
    'primary_dark': '#1e40af',
    'success': '#10b981',      # Green
    'danger': '#ef4444',       # Red
    'warning': '#f59e0b',      # Orange
    'bg_dark': '#1e293b',      # Dark blue-gray
    'bg_light': '#f8fafc',
    'text_dark': '#0f172a',
    'text_light': '#64748b',
    'border': '#e2e8f0'
}

# --------------------------------------------------

def load_blacklist():
    if not os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, "w", encoding="utf-8") as f:
            f.write("Python\nOpenVPN\n")
    with open(BLACKLIST_FILE, "r", encoding="utf-8") as f:
        items = [line.strip() for line in f.readlines() if line.strip()]
    return items

def save_blacklist(items):
    with open(BLACKLIST_FILE, "w", encoding="utf-8") as f:
        for it in items:
            f.write(it.strip() + "\n")

def send_email_with_attachment(subject, html_body, attachment_path=None):
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECIPIENT_EMAIL
        msg['Subject'] = subject

        msg.attach(MIMEText(html_body, 'html'))

        if attachment_path and os.path.exists(attachment_path):
            with open(attachment_path, "rb") as af:
                part = MIMEBase('application', "octet-stream")
                part.set_payload(af.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', 'attachment', filename=os.path.basename(attachment_path))
                msg.attach(part)

        s = smtplib.SMTP('smtp.gmail.com', 587, timeout=30)
        s.starttls()
        s.login(SENDER_EMAIL, SENDER_PASSWORD)
        s.sendmail(SENDER_EMAIL, RECIPIENT_EMAIL, msg.as_string())
        s.quit()
        print("Email sent to", RECIPIENT_EMAIL)
        return True
    except Exception as e:
        print("Failed to send email:", e)
        return False

def get_installed_software_list():
    raw_file = os.path.join(APP_DIR, "unformated_soft.txt")
    try:
        os.system(f'reg query HKLM\\SOFTWARE > "{raw_file}"')
    except Exception as e:
        print("Registry query failed:", e)
        return []

    names = []
    try:
        with open(raw_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        for line in lines:
            line = line.strip()
            if not line or "SOFTWARE\\" not in line:
                continue
            name = line.split("SOFTWARE\\")[-1].strip()
            if not name or len(name) > 60 and name.count('-') >= 2:
                continue
            names.append(name)
    except Exception as e:
        print("Parsing registry dump failed:", e)
    
    try:
        with open(SOFT_LIST_FILE, "w", encoding="utf-8") as f:
            for n in names:
                f.write(n + "\n")
    except:
        pass
    return names

def make_zip_report(zip_name="Alldata.zip"):
    zip_path = os.path.join(APP_DIR, zip_name)
    with ZipFile(zip_path, "w") as zf:
        for fn in os.listdir(SCREEN_DIR):
            zf.write(os.path.join(SCREEN_DIR, fn), arcname=fn)
        if os.path.exists(SOFT_LIST_FILE):
            zf.write(SOFT_LIST_FILE, arcname=os.path.basename(SOFT_LIST_FILE))
    return zip_path

class AdminMonitor(threading.Thread):
    def __init__(self, scan_hour, screen_interval_min, work_hours, blacklist, ui_callback=None):
        super().__init__(daemon=True)
        self.scan_hour = scan_hour
        self.screen_interval = max(1, int(screen_interval_min))
        self.work_hours = max(1, int(work_hours))
        self.blacklist = blacklist[:]
        self.ui_callback = ui_callback
        self._stop_event = threading.Event()

    def log(self, txt):
        print("[Monitor]", txt)
        if self.ui_callback:
            try:
                self.ui_callback(txt)
            except:
                pass

    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()

    def run_daily_scan(self):
        names = get_installed_software_list()
        found = []
        for bl in self.blacklist:
            for n in names:
                if bl.lower() in n.lower():
                    found.append((bl, n))
        
        soft_lines = "\n".join(names)
        with open(os.path.join(APP_DIR, "soft_report.txt"), "w", encoding="utf-8") as f:
            f.write(soft_lines)
        
        if found:
            zip_path = make_zip_report()
            found_list_html = "<br>".join([f"{b} matched {n}" for b, n in found])
            html = f"""
            <html><body>
            <h3 style='color:red;'>Blacklisted Software Detected</h3>
            <p>{found_list_html}</p>
            <p>Full installed software list attached.</p>
            </body></html>
            """
            self.log("⚠️ Blacklisted software detected: " + ", ".join([f"{b}->{n}" for b, n in found]))
            send_email_with_attachment("Blacklisted Software Detected!!", html, zip_path)
        else:
            self.log("✓ Daily scan: no blacklisted software found.")

    def run(self):
        shots_per_report = max(1, int((self.work_hours * 60) / self.screen_interval))
        self.log(f"🚀 Monitor started. Screenshot interval: {self.screen_interval} min. Daily scan: {self.scan_hour}:00")
        shot_count = 0
        
        while not self.stopped():
            try:
                now = time.localtime()
                stamp = time.strftime("%Y-%m-%d_%H-%M-%S", now)
                fname = os.path.join(SCREEN_DIR, f"{stamp}.png")
                img = pyautogui.screenshot()
                img.save(fname)
                self.log(f"📸 Screenshot captured: {stamp}")
                shot_count += 1
            except Exception as e:
                self.log("❌ Screenshot failed: " + str(e))

            if shot_count >= shots_per_report:
                try:
                    zip_path = make_zip_report()
                    html = f"<html><body><p>Automated screenshot report: {shot_count} screenshots attached.</p></body></html>"
                    send_email_with_attachment("Automated Screenshot Report", html, zip_path)
                    self.log(f"📧 Sent screenshot report with {shot_count} images.")
                    for fn in os.listdir(SCREEN_DIR):
                        try:
                            os.remove(os.path.join(SCREEN_DIR, fn))
                        except:
                            pass
                    shot_count = 0
                except Exception as e:
                    self.log("❌ Failed to zip/send screenshots: " + str(e))

            try:
                if time.localtime().tm_hour == int(self.scan_hour):
                    self.log("🔍 Running daily software scan...")
                    self.run_daily_scan()
                    time.sleep(61)
            except Exception as e:
                self.log("❌ Error while scheduled scanning: " + str(e))

            for _ in range(int(self.screen_interval * 60)):
                if self.stopped():
                    break
                time.sleep(1)

def virustotal_file_scan(filepath):
    if not os.path.exists(filepath):
        return False, "file_not_found", "File does not exist"

    headers = {"x-apikey": VT_API_KEY}
    url_upload = "https://www.virustotal.com/api/v3/files"
    try:
        with open(filepath, "rb") as f:
            files = {"file": (os.path.basename(filepath), f)}
            r = requests.post(url_upload, files=files, headers=headers, timeout=60)
        if r.status_code not in (200, 201):
            return False, "upload_failed", f"Upload failed: {r.status_code} {r.text}"
        j = r.json()
        analysis_id = j.get("data", {}).get("id")
        if not analysis_id:
            return False, "no_analysis_id", j

        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for _ in range(20):
            ra = requests.get(analysis_url, headers=headers, timeout=30)
            if ra.status_code != 200:
                time.sleep(3)
                continue
            ja = ra.json()
            status = ja.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                stats = ja.get("data", {}).get("attributes", {}).get("stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                if malicious > 0:
                    return True, "malicious", ja
                elif suspicious > 0:
                    return True, "suspicious", ja
                else:
                    return True, "not_malicious", ja
            time.sleep(3)
        return False, "timeout", "Analysis not completed in time"
    except Exception as e:
        return False, "exception", str(e)

# -------------------- MODERN GUI --------------------

class ModernButton(tk.Canvas):
    def __init__(self, parent, text, command, bg_color=COLORS['primary'], fg_color='white', **kwargs):
        super().__init__(parent, highlightthickness=0, **kwargs)
        self.bg_color = bg_color
        self.fg_color = fg_color
        self.command = command
        self.text = text
        
        self.config(bg=parent.cget('bg'), height=40, width=150)
        self.draw()
        
        self.bind('<Enter>', self.on_enter)
        self.bind('<Leave>', self.on_leave)
        self.bind('<Button-1>', lambda e: self.command())
        
    def draw(self, hover=False):
        self.delete('all')
        color = self.bg_color if not hover else COLORS['primary_dark']
        self.create_rectangle(0, 0, 200, 40, fill=color, outline='', tags='bg')
        self.create_text(75, 20, text=self.text, fill=self.fg_color, font=('Segoe UI', 10, 'bold'))
        
    def on_enter(self, e):
        self.draw(hover=True)
        
    def on_leave(self, e):
        self.draw(hover=False)

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SecMon - Security Monitoring System")
        self.geometry("1000x700")
        self.configure(bg=COLORS['bg_light'])
        
        # Modern style configuration
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure styles
        style.configure('Title.TLabel', font=('Segoe UI', 24, 'bold'), 
                       foreground=COLORS['text_dark'], background=COLORS['bg_light'])
        style.configure('Subtitle.TLabel', font=('Segoe UI', 12), 
                       foreground=COLORS['text_light'], background=COLORS['bg_light'])
        style.configure('Card.TFrame', background='white', relief='flat')
        style.configure('Modern.TButton', font=('Segoe UI', 10), padding=10)
        style.configure('Modern.TEntry', padding=8)
        style.configure('Modern.TCombobox', padding=8)

        self.sender_email = SENDER_EMAIL
        self.sender_password = SENDER_PASSWORD

        self.container = tk.Frame(self, bg=COLORS['bg_light'])
        self.container.pack(fill="both", expand=True)
        self.frames = {}

        for F in (LoginPage, AdminPage, UserPage):
            page = F(self.container, self)
            self.frames[F] = page
            page.place(relx=0, rely=0, relwidth=1, relheight=1)

        self.show_frame(LoginPage)
        self.monitor_thread = None

    def show_frame(self, page_cls):
        frame = self.frames[page_cls]
        frame.tkraise()

    def start_monitoring(self, scan_hour, screen_interval, work_hours, blacklist, ui_callback=None):
        if self.monitor_thread and getattr(self.monitor_thread, "is_alive", lambda: False)():
            try:
                self.monitor_thread.stop()
            except:
                pass
        self.monitor_thread = AdminMonitor(scan_hour, screen_interval, work_hours, blacklist, ui_callback)
        self.monitor_thread.start()
        return self.monitor_thread

class LoginPage(tk.Frame):
    def __init__(self, parent, controller: App):
        super().__init__(parent, bg=COLORS['bg_light'])
        self.controller = controller
        
        # Center card
        card = tk.Frame(self, bg='white', padx=60, pady=40)
        card.place(relx=0.5, rely=0.5, anchor='center')
        
        # Add shadow effect
        shadow = tk.Frame(self, bg='#e2e8f0')
        shadow.place(relx=0.5, rely=0.502, anchor='center', 
                    width=card.winfo_reqwidth()+4, height=card.winfo_reqheight()+4)
        card.lift()
        
        # Logo/Icon
        icon = tk.Canvas(card, width=80, height=80, bg='white', highlightthickness=0)
        icon.pack(pady=(0, 20))
        icon.create_oval(10, 10, 70, 70, fill=COLORS['primary'], outline='')
        icon.create_text(40, 40, text='🔒', font=('Segoe UI', 32))
        
        # Title
        ttk.Label(card, text="SecMon Login", style='Title.TLabel').pack(pady=(0, 10))
        ttk.Label(card, text="Security Monitoring System", style='Subtitle.TLabel').pack(pady=(0, 30))
        
        # Form
        form = tk.Frame(card, bg='white')
        form.pack(pady=10)
        
        # Role selection
        tk.Label(form, text="Role", font=('Segoe UI', 10), bg='white', 
                fg=COLORS['text_light'], anchor='w').grid(row=0, column=0, sticky='w', pady=(0, 5))
        self.role_var = tk.StringVar(value="admin")
        role_combo = ttk.Combobox(form, textvariable=self.role_var, 
                                  values=["admin", "user"], state="readonly", 
                                  width=30, font=('Segoe UI', 10))
        role_combo.grid(row=1, column=0, pady=(0, 20), ipady=5)
        
        # Username
        tk.Label(form, text="Username", font=('Segoe UI', 10), bg='white', 
                fg=COLORS['text_light'], anchor='w').grid(row=2, column=0, sticky='w', pady=(0, 5))
        self.username = ttk.Entry(form, width=32, font=('Segoe UI', 10))
        self.username.grid(row=3, column=0, pady=(0, 20), ipady=5)
        
        # Password
        tk.Label(form, text="Password", font=('Segoe UI', 10), bg='white', 
                fg=COLORS['text_light'], anchor='w').grid(row=4, column=0, sticky='w', pady=(0, 5))
        self.password = ttk.Entry(form, width=32, show="●", font=('Segoe UI', 10))
        self.password.grid(row=5, column=0, pady=(0, 30), ipady=5)
        
        # Login button
        login_btn = tk.Button(form, text="Login", command=self.login_action,
                             bg=COLORS['primary'], fg='white', font=('Segoe UI', 11, 'bold'),
                             border=0, padx=40, pady=12, cursor='hand2',
                             activebackground=COLORS['primary_dark'], activeforeground='white')
        login_btn.grid(row=6, column=0, pady=(0, 20))
        
        # Demo credentials
        info_frame = tk.Frame(card, bg='#f1f5f9', padx=20, pady=15)
        info_frame.pack(pady=(20, 0), fill='x')
        tk.Label(info_frame, text="Demo Credentials", font=('Segoe UI', 9, 'bold'),
                bg='#f1f5f9', fg=COLORS['text_dark']).pack()
        tk.Label(info_frame, text="Admin: admin / admin123\nUser: user / user123",
                font=('Segoe UI', 9), bg='#f1f5f9', fg=COLORS['text_light']).pack(pady=(5, 0))
        
        self.credentials = {
            "admin": {"username": "admin", "password": "admin123"},
            "user": {"username": "user", "password": "user123"}
        }

    def login_action(self):
        role = self.role_var.get()
        u = self.username.get().strip()
        p = self.password.get().strip()
        cred = self.credentials.get(role, {})
        if u == cred.get("username") and p == cred.get("password"):
            if role == "admin":
                self.controller.show_frame(AdminPage)
                admin_frame = self.controller.frames[AdminPage]
                admin_frame.auto_start_monitoring_on_show()
            else:
                self.controller.show_frame(UserPage)
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

class AdminPage(tk.Frame):
    def __init__(self, parent, controller: App):
        super().__init__(parent, bg=COLORS['bg_light'])
        self.controller = controller
        
        # Header
        header = tk.Frame(self, bg='white', height=80)
        header.pack(fill='x', padx=20, pady=(20, 0))
        header.pack_propagate(False)
        
        tk.Label(header, text="🛡️ Admin Control Panel", font=('Segoe UI', 20, 'bold'),
                bg='white', fg=COLORS['text_dark']).pack(side='left', padx=20, pady=20)
        
        logout_btn = tk.Button(header, text="Logout", command=lambda: controller.show_frame(LoginPage),
                              bg=COLORS['danger'], fg='white', font=('Segoe UI', 9, 'bold'),
                              border=0, padx=20, pady=8, cursor='hand2')
        logout_btn.pack(side='right', padx=20, pady=20)
        
        # Main content
        content = tk.Frame(self, bg=COLORS['bg_light'])
        content.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Left panel - Settings
        left_card = tk.Frame(content, bg='white', padx=25, pady=25)
        left_card.pack(side='left', fill='both', padx=(0, 10))
        
        tk.Label(left_card, text="⚙️ Monitoring Settings", font=('Segoe UI', 14, 'bold'),
                bg='white', fg=COLORS['text_dark']).pack(anchor='w', pady=(0, 20))
        
        # Daily scan hour
        self._create_setting(left_card, "Daily Scan Hour (0-23)", 'scan_hour_var', 
                           DEFAULT_DAILY_SCAN_HOUR, 'spinbox', from_=0, to=23)
        
        # Screenshot interval
        self._create_setting(left_card, "Screenshot Interval (minutes)", 'screen_interval_var',
                           DEFAULT_SCREEN_INTERVAL_MIN, 'entry')
        
        # Work hours
        self._create_setting(left_card, "Work Hours (for report)", 'work_hours_var',
                           DEFAULT_WORK_HOURS, 'entry')
        
        # Control buttons
        btn_frame = tk.Frame(left_card, bg='white')
        btn_frame.pack(pady=(25, 0), fill='x')
        
        self.start_btn = tk.Button(btn_frame, text="▶ Start Monitoring",
                                   command=self.start_monitor,
                                   bg=COLORS['success'], fg='white',
                                   font=('Segoe UI', 10, 'bold'),
                                   border=0, pady=12, cursor='hand2')
        self.start_btn.pack(fill='x', pady=(0, 10))
        
        self.stop_btn = tk.Button(btn_frame, text="⏸ Stop Monitoring",
                                  command=self.stop_monitor,
                                  bg=COLORS['warning'], fg='white',
                                  font=('Segoe UI', 10, 'bold'),
                                  border=0, pady=12, cursor='hand2')
        self.stop_btn.pack(fill='x', pady=(0, 10))
        
        scan_btn = tk.Button(btn_frame, text="🔍 Quick Scan Now",
                            command=self.run_quick_scan,
                            bg=COLORS['primary'], fg='white',
                            font=('Segoe UI', 10, 'bold'),
                            border=0, pady=12, cursor='hand2')
        scan_btn.pack(fill='x')
        
        # Right panel - Blacklist & Logs
        right_card = tk.Frame(content, bg='white', padx=25, pady=25)
        right_card.pack(side='left', fill='both', expand=True, padx=(10, 0))
        
        tk.Label(right_card, text="📋 Blacklist Management", font=('Segoe UI', 14, 'bold'),
                bg='white', fg=COLORS['text_dark']).pack(anchor='w', pady=(0, 15))
        
        # Blacklist controls
        bl_control = tk.Frame(right_card, bg='white')
        bl_control.pack(fill='x', pady=(0, 10))
        
        self.bl_entry = tk.Entry(bl_control, font=('Segoe UI', 10), relief='solid', bd=1)
        self.bl_entry.pack(side='left', fill='x', expand=True, ipady=5, padx=(0, 5))
        
        add_btn = tk.Button(bl_control, text="Add", command=self.add_blacklist,
                           bg=COLORS['success'], fg='white', font=('Segoe UI', 9, 'bold'),
                           border=0, padx=15, pady=6, cursor='hand2')
        add_btn.pack(side='left', padx=(0, 5))
        
        remove_btn = tk.Button(bl_control, text="Remove", command=self.remove_blacklist,
                              bg=COLORS['danger'], fg='white', font=('Segoe UI', 9, 'bold'),
                              border=0, padx=15, pady=6, cursor='hand2')
        remove_btn.pack(side='left', padx=(0, 5))
        
        save_btn = tk.Button(bl_control, text="Save", command=self.save_blacklist_gui,
                            bg=COLORS['primary'], fg='white', font=('Segoe UI', 9, 'bold'),
                            border=0, padx=15, pady=6, cursor='hand2')
        save_btn.pack(side='left')
        
        # Blacklist listbox
        bl_frame = tk.Frame(right_card, bg='white')
        bl_frame.pack(fill='both', pady=(0, 20))
        
        scrollbar = tk.Scrollbar(bl_frame)
        scrollbar.pack(side='right', fill='y')
        
        self.blacklist_box = tk.Listbox(bl_frame, font=('Segoe UI', 10), 
                                        relief='solid', bd=1,
                                        yscrollcommand=scrollbar.set, height=8)
        self.blacklist_box.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=self.blacklist_box.yview)
        
        for it in load_blacklist():
            self.blacklist_box.insert(tk.END, it)
        
        # Log section
        tk.Label(right_card, text="📊 Activity Log", font=('Segoe UI', 12, 'bold'),
                bg='white', fg=COLORS['text_dark']).pack(anchor='w', pady=(10, 10))
        
        log_frame = tk.Frame(right_card, bg='white')
        log_frame.pack(fill='both', expand=True)
        
        log_scroll = tk.Scrollbar(log_frame)
        log_scroll.pack(side='right', fill='y')
        
        self.log_text = tk.Text(log_frame, font=('Consolas', 9), relief='solid', bd=1,
                               yscrollcommand=log_scroll.set, wrap='word', bg='#f8fafc')
        self.log_text.pack(side='left', fill='both', expand=True)
        log_scroll.config(command=self.log_text.yview)

    def _create_setting(self, parent, label_text, var_name, default_val, widget_type, **kwargs):
        frame = tk.Frame(parent, bg='white')
        frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(frame, text=label_text, font=('Segoe UI', 10),
                bg='white', fg=COLORS['text_light']).pack(anchor='w', pady=(0, 8))
        
        if widget_type == 'spinbox':
            var = tk.IntVar(value=default_val)
            widget = tk.Spinbox(frame, textvariable=var, font=('Segoe UI', 10),
                               relief='solid', bd=1, **kwargs)
            widget.pack(fill='x', ipady=4)
        else:
            var = tk.IntVar(value=default_val)
            widget = tk.Entry(frame, textvariable=var, font=('Segoe UI', 10),
                             relief='solid', bd=1)
            widget.pack(fill='x', ipady=4)
        
        setattr(self, var_name, var)

    def log(self, txt):
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {txt}\n")
        self.log_text.see(tk.END)

    def add_blacklist(self):
        v = self.bl_entry.get().strip()
        if v:
            self.blacklist_box.insert(tk.END, v)
            self.bl_entry.delete(0, tk.END)

    def remove_blacklist(self):
        sel = list(self.blacklist_box.curselection())
        for i in reversed(sel):
            self.blacklist_box.delete(i)

    def save_blacklist_gui(self):
        items = [self.blacklist_box.get(i) for i in range(self.blacklist_box.size())]
        save_blacklist(items)
        self.log("✓ Blacklist saved successfully")

    def run_quick_scan(self):
        self.log("🔍 Initiating quick scan...")
        names = get_installed_software_list()
        found = []
        bl = [self.blacklist_box.get(i) for i in range(self.blacklist_box.size())]
        for b in bl:
            for n in names:
                if b.lower() in n.lower():
                    found.append((b, n))
        if found:
            self.log(f"⚠️ Found {len(found)} blacklisted items: " + ", ".join([f"{b}->{n}" for b, n in found]))
            zip_path = make_zip_report()
            html = f"<html><body><p>Quick scan detected blacklisted software: <br>{'<br>'.join([f'{b} matched {n}' for b,n in found])}</p></body></html>"
            send_email_with_attachment("Quick: Blacklisted Software Detected", html, zip_path)
            self.log("📧 Report emailed successfully")
        else:
            self.log("✓ No blacklisted software found")

    def start_monitor(self):
        bl = [self.blacklist_box.get(i) for i in range(self.blacklist_box.size())]
        scan_hour = self.scan_hour_var.get()
        interval = self.screen_interval_var.get()
        work_hours = self.work_hours_var.get()
        self.controller.start_monitoring(scan_hour, interval, work_hours, bl, ui_callback=self.log)
        self.log("🚀 Monitoring started successfully")

    def stop_monitor(self):
        if self.controller.monitor_thread:
            try:
                self.controller.monitor_thread.stop()
                self.log("⏸ Monitoring stopped")
            except:
                self.log("❌ Failed to stop monitor")

    def auto_start_monitoring_on_show(self):
        self.start_monitor()

class UserPage(tk.Frame):
    def __init__(self, parent, controller: App):
        super().__init__(parent, bg=COLORS['bg_light'])
        self.controller = controller
        
        # Header
        header = tk.Frame(self, bg='white', height=80)
        header.pack(fill='x', padx=20, pady=(20, 0))
        header.pack_propagate(False)
        
        tk.Label(header, text="🔍 User Panel - Virus Scanner", font=('Segoe UI', 20, 'bold'),
                bg='white', fg=COLORS['text_dark']).pack(side='left', padx=20, pady=20)
        
        logout_btn = tk.Button(header, text="Logout", command=lambda: controller.show_frame(LoginPage),
                              bg=COLORS['danger'], fg='white', font=('Segoe UI', 9, 'bold'),
                              border=0, padx=20, pady=8, cursor='hand2')
        logout_btn.pack(side='right', padx=20, pady=20)
        
        # Main card
        card = tk.Frame(self, bg='white', padx=50, pady=40)
        card.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Icon
        icon_canvas = tk.Canvas(card, width=100, height=100, bg='white', highlightthickness=0)
        icon_canvas.pack(pady=(0, 30))
        icon_canvas.create_oval(10, 10, 90, 90, fill=COLORS['primary'], outline='')
        icon_canvas.create_text(50, 50, text='🦠', font=('Segoe UI', 40))
        
        tk.Label(card, text="VirusTotal File Scanner", font=('Segoe UI', 18, 'bold'),
                bg='white', fg=COLORS['text_dark']).pack(pady=(0, 10))
        tk.Label(card, text="Upload a file to scan for viruses and malware", 
                font=('Segoe UI', 11), bg='white', fg=COLORS['text_light']).pack(pady=(0, 40))
        
        # File selection
        file_frame = tk.Frame(card, bg='white')
        file_frame.pack(fill='x', pady=(0, 30))
        
        self.filepath_var = tk.StringVar()
        file_entry = tk.Entry(file_frame, textvariable=self.filepath_var, 
                             font=('Segoe UI', 10), relief='solid', bd=1, state='readonly')
        file_entry.pack(side='left', fill='x', expand=True, ipady=8, padx=(0, 10))
        
        browse_btn = tk.Button(file_frame, text="📁 Browse", command=self.browse_file,
                              bg=COLORS['primary'], fg='white', font=('Segoe UI', 10, 'bold'),
                              border=0, padx=25, pady=10, cursor='hand2')
        browse_btn.pack(side='left')
        
        # Scan button
        scan_btn = tk.Button(card, text="🔍 Scan File", command=self.scan_file,
                            bg=COLORS['success'], fg='white', font=('Segoe UI', 12, 'bold'),
                            border=0, padx=50, pady=15, cursor='hand2',
                            activebackground='#059669', activeforeground='white')
        scan_btn.pack(pady=(0, 30))
        
        # Result display
        result_frame = tk.Frame(card, bg='#f8fafc', padx=30, pady=25)
        result_frame.pack(fill='x')
        
        tk.Label(result_frame, text="Scan Result:", font=('Segoe UI', 11, 'bold'),
                bg='#f8fafc', fg=COLORS['text_dark']).pack()
        
        self.result_label = tk.Label(result_frame, text="No scan performed yet", 
                                     font=('Segoe UI', 14, 'bold'),
                                     bg='#f8fafc', fg=COLORS['text_light'])
        self.result_label.pack(pady=(10, 0))
        
        # Info text
        info = tk.Label(card, text="Powered by VirusTotal API", 
                       font=('Segoe UI', 9), bg='white', fg=COLORS['text_light'])
        info.pack(side='bottom', pady=(30, 0))

    def browse_file(self):
        f = filedialog.askopenfilename(title="Select file to scan")
        if f:
            self.filepath_var.set(f)

    def scan_file(self):
        path = self.filepath_var.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showerror("File Error", "Please select a valid file to scan")
            return

        self.result_label.config(text="⏳ Scanning... Please wait", fg=COLORS['warning'])
        self.update_idletasks()

        def do_scan():
            ok, verdict, info = virustotal_file_scan(path)
            
            if ok:
                if verdict == "malicious":
                    self.result_label.config(text="⚠️ MALICIOUS", fg=COLORS['danger'])
                    body = f"<p>VirusTotal scan result: <strong>MALICIOUS</strong> for file {os.path.basename(path)}</p>"
                elif verdict == "suspicious":
                    self.result_label.config(text="⚠️ SUSPICIOUS", fg=COLORS['warning'])
                    body = f"<p>VirusTotal scan result: <strong>SUSPICIOUS</strong> for file {os.path.basename(path)}</p>"
                else:
                    self.result_label.config(text="✓ NOT MALICIOUS", fg=COLORS['success'])
                    body = f"<p>VirusTotal scan result: <strong>NOT MALICIOUS</strong> for file {os.path.basename(path)}</p>"
                
                send_email_with_attachment("VirusTotal Scan Report", 
                                          f"<html><body>{body}</body></html>")
            else:
                self.result_label.config(text="❌ Scan Error", fg=COLORS['danger'])
                messagebox.showerror("Scan Error", f"Failed to scan: {verdict}\nDetails: {info}")

        threading.Thread(target=do_scan, daemon=True).start()

# Run the application
if __name__ == "__main__":
    if not os.path.exists(APP_DIR):
        os.makedirs(APP_DIR, exist_ok=True)
    if not os.path.exists(BLACKLIST_FILE):
        save_blacklist(["Python", "OpenVPN"])

    if SENDER_PASSWORD == "REPLACE_WITH_APP_PASSWORD":
        print("WARNING: Please edit SENDER_PASSWORD in the script before running email features.")
    
    app = App()
    app.mainloop()