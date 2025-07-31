import hashlib
import os
import re
import requests
import logging
from email import policy
from email.parser import BytesParser

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
                "Phishing Risk Score": self.calculate_risk_score(),
                "Phishing Indicators": "; ".join(self.phishing_indicators) or "None",
                "Body Preview": self.body_content[:200] + "..." if self.body_content else "None",
                "Attachments": "; ".join([f"{a['filename']} (SHA256: {a['hash']})" for a in self.attachments_info]) or "None"
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
        for ip in list(public_ips)[:2]:
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


def main():
    print("Enter .eml file path:")
    file_path = input(">>> ").strip()

    if not os.path.exists(file_path):
        print(f" File not found: {file_path}")
        return

    print(" Enable GeoIP lookup? (y/n):")
    geo_input = input(">>> ").strip().lower()
    geoip_enabled = geo_input == 'y'

    print("Save report to a file? Enter filename or leave blank to skip:")
    output_path = input(">>> ").strip()

    parser_obj = EmailParser(file_path, geoip_enabled=geoip_enabled)
    report = parser_obj.parse_email()

    print("\nEmail Analysis Report:\n")
    print(report)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"\nReport saved to: {output_path}")


if __name__ == "__main__":
    main()
