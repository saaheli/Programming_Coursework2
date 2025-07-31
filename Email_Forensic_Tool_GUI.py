import os, re, csv, hashlib, logging, threading, requests
from fpdf import FPDF
from email import policy
from email.parser import BytesParser
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk, messagebox, BooleanVar
from tkinterdnd2 import DND_FILES, TkinterDnD

logging.basicConfig(filename='log.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class EmailParser:
    def __init__(self, file_path, geoip_enabled=True):
        self.file_path = file_path
        self.geoip_enabled = geoip_enabled
        self.latest_email_data = {}
        self.header_analysis = {}
        self.phishing_indicators = []
        self.body_content = ""
        self.attachments_info = []

    def parse_email(self):
        try:
            with open(self.file_path, 'rb') as file:
                msg = BytesParser(policy=policy.default).parse(file)

            message_id = msg.get("Message-ID", "N/A")
            date = msg.get("Date", "N/A")
            hash_input = f"{message_id}{date}".encode("utf-8")
            metadata_hash = hashlib.sha256(hash_input).hexdigest()

            auth_results = msg.get("Authentication-Results", "").lower()
            spf_status = "Pass" if "spf=pass" in auth_results else "Fail"
            dkim_status = "Pass" if "dkim=pass" in auth_results else "Fail"
            dmarc_status = "Pass" if "dmarc=pass" in auth_results else "Fail"

            received_headers = msg.get_all("Received", [])
            geoip_info = self.get_geoip_info(received_headers) if self.geoip_enabled else "Disabled"

            self.header_analysis = {
                "X-Mailer": msg.get("X-Mailer", "N/A"),
                "User-Agent": msg.get("User-Agent", "N/A"),
                "Return-Path": msg.get("Return-Path", "N/A"),
                "Received": "\n".join(received_headers) if received_headers else "N/A"
            }

            self.detect_phishing_indicators(msg)
            self.extract_body(msg)
            self.extract_attachments(msg)

            email_details = {
                "Subject": msg.get("Subject", "N/A"),
                "From": msg.get("From", "N/A"),
                "To": msg.get("To", "N/A"),
                "CC": msg.get("Cc", "N/A"),
                "BCC": msg.get("Bcc", "N/A"),
                "Reply-To": msg.get("Reply-To", "N/A"),
                "Date": date,
                "Message-ID": message_id,
                "MIME Version": msg.get("MIME-Version", "N/A"),
                "Content Type": msg.get_content_type(),
                "Encoding": msg.get("Content-Transfer-Encoding", "N/A"),
                "SPF Status": spf_status,
                "DKIM Status": dkim_status,
                "DMARC Status": dmarc_status,
                "Metadata SHA256 Hash": metadata_hash,
                "GeoIP Info": geoip_info,
                "Phishing Risk Score": self.calculate_risk_score()
            }

            self.latest_email_data = email_details
            return "\n".join([f"{k}: {v}" for k, v in email_details.items()])
        except Exception as e:
            logging.error(f"Error parsing email: {e}")
            return f"Error parsing email: {e}"

    def extract_body(self, msg):
        body = []
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body.append(part.get_payload(decode=True).decode(errors="ignore"))
        else:
            body.append(msg.get_payload(decode=True).decode(errors="ignore"))
        self.body_content = "\n".join(body).strip()

    def extract_attachments(self, msg):
        if not os.path.exists("attachments"):
            os.makedirs("attachments")
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename()
                payload = part.get_payload(decode=True)
                if filename and payload:
                    filepath = os.path.join("attachments", filename)
                    with open(filepath, "wb") as f:
                        f.write(payload)
                    sha256 = hashlib.sha256(payload).hexdigest()
                    self.attachments_info.append({"filename": filename, "hash": sha256})

    def get_geoip_info(self, headers):
        ip_regex = r'(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)(?!\d)'
        public_ips = set()
        for h in headers:
            found_ips = re.findall(ip_regex, h)
            public_ips.update(ip for ip in found_ips if not ip.startswith(("10.", "192.168.", "172.")))

        geo_info = []
        for i, ip in enumerate(list(public_ips)[:2]):
            try:
                r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=1)
                data = r.json()
                location = f"{ip} - {data.get('city', '')}, {data.get('region', '')}, {data.get('country', '')}"
                geo_info.append(location.strip(" - ,"))
            except Exception as e:
                logging.warning(f"GeoIP failed for {ip}: {e}")
                geo_info.append(f"{ip} - Lookup failed")
        return "\n".join(geo_info) if geo_info else "N/A"

    def detect_phishing_indicators(self, msg):
        indicators = []
        from_field = msg.get("From", "")
        reply_to = msg.get("Reply-To", "")
        return_path = msg.get("Return-Path", "")
        subject = msg.get("Subject", "")

        from_email = re.findall(r"<(.*?)>", from_field)
        reply_to_email = re.findall(r"<(.*?)>", reply_to)
        return_path_email = return_path.strip("<>")

        if from_email and reply_to_email and from_email[0].split("@")[-1] != reply_to_email[0].split("@")[-1]:
            indicators.append("Reply-To domain differs from From domain.")
        if from_email and return_path_email and from_email[0] != return_path_email:
            indicators.append("From and Return-Path do not match.")
        if re.search(r"(urgent|password|verify|login|invoice)", subject, re.IGNORECASE):
            indicators.append("Suspicious keyword in Subject.")
        self.phishing_indicators = indicators

    def calculate_risk_score(self):
        score = len(self.phishing_indicators) * 3
        return "High " if score >= 6 else "Medium " if score >= 3 else "Low "


class ForensicEmailAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Email Forensic Tool")
        self.root.geometry("1200x750")
        self.file_path = ""
        self.result_text = ""
        self.geoip_enabled = BooleanVar(value=True)

        self.label = tk.Label(root, text="Drag & Drop or Browse Email File (.eml)", font=("Arial", 12))
        self.label.pack(pady=10)

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Arial", 10), height=10, state='disabled')
        self.text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        btn_frame = tk.Frame(root)
        btn_frame.pack()

        tk.Button(btn_frame, text="Browse", bg="blue", fg="white", command=self.load_email, width=16).grid(row=0, column=0, padx=5)
        tk.Button(btn_frame, text="Analyze Email", bg="green", fg="white", command=self.run_analysis_thread, width=16).grid(row=0, column=1, padx=5)
        tk.Button(btn_frame, text="Save Report", bg="orange", fg="white", command=self.save_report, width=16).grid(row=0, column=2, padx=5)

        self.export_menu = tk.Menubutton(btn_frame, text="Export", bg="purple", fg="white", width=16)
        self.export_menu.menu = tk.Menu(self.export_menu, tearoff=0)
        self.export_menu["menu"] = self.export_menu.menu
        self.export_menu.menu.add_command(label="Export PDF", command=self.export_pdf)
        self.export_menu.menu.add_command(label="Export CSV", command=self.export_csv)
        self.export_menu.grid(row=0, column=3, padx=5)

        tk.Button(btn_frame, text="Clear", bg="red", fg="white", command=self.clear_text, width=16).grid(row=0, column=4, padx=5)
        tk.Button(btn_frame, text="Exit", bg="gray", fg="white", command=root.quit, width=16).grid(row=0, column=5, padx=5)

        tk.Checkbutton(root, text="Enable GeoIP Lookup", variable=self.geoip_enabled).pack(pady=5)

        self.tabs = ttk.Notebook(root)
        self.header_tab = scrolledtext.ScrolledText(self.tabs, wrap=tk.WORD, font=("Arial", 10), state='disabled')
        self.phishing_tab = scrolledtext.ScrolledText(self.tabs, wrap=tk.WORD, font=("Arial", 10), state='disabled')
        self.body_tab = scrolledtext.ScrolledText(self.tabs, wrap=tk.WORD, font=("Arial", 10), state='disabled')
        self.attachments_tab = scrolledtext.ScrolledText(self.tabs, wrap=tk.WORD, font=("Arial", 10), state='disabled')
        self.tabs.add(self.header_tab, text="Header Analysis")
        self.tabs.add(self.phishing_tab, text="Phishing Indicators")
        self.tabs.add(self.body_tab, text="Email Body")
        self.tabs.add(self.attachments_tab, text="Attachments")
        self.tabs.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        root.drop_target_register(DND_FILES)
        root.dnd_bind('<<Drop>>', self.drop_email)

    def drop_email(self, event):
        self.file_path = event.data.strip("{}")
        self.label.config(text=f"Loaded: {os.path.basename(self.file_path)}")

    def load_email(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("Email Files", "*.eml")])
        if self.file_path:
            self.label.config(text=f"Loaded: {os.path.basename(self.file_path)}")

    def run_analysis_thread(self):
        threading.Thread(target=self.analyze_email).start()

    def analyze_email(self):
        if not self.file_path:
            messagebox.showerror("File Error", "No email file selected.")
            return
        self.update_text_area(self.text_area, "🔍 Analyzing... Please wait.\n")
        parser = EmailParser(self.file_path, self.geoip_enabled.get())
        self.parser = parser
        self.result_text = parser.parse_email()
        self.update_text_area(self.text_area, self.result_text)
        self.update_text_area(self.header_tab, "\n".join([f"{k}: {v}" for k, v in parser.header_analysis.items()]))
        self.update_text_area(self.phishing_tab, "\n".join([f"{i}" for i in parser.phishing_indicators]) or "No phishing indicators.")
        self.update_text_area(self.body_tab, parser.body_content or "No body content.")
        attachments = "\n".join([f"{a['filename']} (SHA256: {a['hash']})" for a in parser.attachments_info]) or "No attachments."
        self.update_text_area(self.attachments_tab, attachments)

    def update_text_area(self, widget, text):
        widget.config(state='normal')
        widget.delete('1.0', tk.END)
        widget.insert(tk.END, text)
        widget.config(state='disabled')

    def save_report(self):
        if not self.result_text:
            messagebox.showwarning("Warning", "No email analyzed yet.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.result_text)
            messagebox.showinfo("Saved", f"Report saved at:\n{path}")

    def export_pdf(self):
        if not self.result_text:
            messagebox.showwarning("Warning", "Analyze email before exporting.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Files", "*.pdf")])
        if path:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            for line in self.result_text.split('\n'):
                pdf.cell(200, 10, txt=line.encode("latin-1", "replace").decode("latin-1"), ln=True)
            pdf.output(path)
            messagebox.showinfo("Exported", f"PDF exported at:\n{path}")

    def export_csv(self):
        if not self.result_text or not hasattr(self, "parser"):
            messagebox.showwarning("Warning", "Analyze email before exporting.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if path:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Field", "Value"])
                for key, value in self.parser.latest_email_data.items():
                    writer.writerow([key, value])
            messagebox.showinfo("Exported", f"CSV exported at:\n{path}")

    def clear_text(self):
        self.update_text_area(self.text_area, "")
        self.update_text_area(self.header_tab, "")
        self.update_text_area(self.phishing_tab, "")
        self.update_text_area(self.body_tab, "")
        self.update_text_area(self.attachments_tab, "")
        self.label.config(text="Drag & Drop or Browse Email File (.eml)")
        self.file_path = ""

if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = ForensicEmailAnalyzer(root)
    root.mainloop()
