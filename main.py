import email
import hashlib
import os
import re
import difflib
from urllib.parse import urlparse

path = './'
listing = os.listdir(path)

BRANDS = {
    "paypal.com", "google.com", "microsoft.com", "apple.com",
    "amazon.com", "netflix.com", "facebook.com", "instagram.com",
    "outlook.com", "bankofamerica.com",
}

ALLOWLIST = {
    "google.com", "googleapis.com", "gstatic.com", "googletagmanager.com",
    "microsoft.com", "apple.com", "cloudflare.com", "w3.org",
}

with open("shortener") as fh:
    SHORTENERS = {
        line.strip()
        for line in fh
        if line.strip() and not line.startswith("#")
    }
print(len(SHORTENERS), "shorteners loaded")

for file in listing:
    if file.lower().endswith(".eml"):
        msg = email.message_from_file(open(file))
        for part in msg.walk():
            fname = part.get_filename()
            ctype = part.get_content_type()

            if fname is not None:
                decodedAttachment = part.get_payload(decode=True)
                f = hashlib.sha256(decodedAttachment).hexdigest()
                print(f"{fname} -> {f}")

            elif ctype == "text/plain" or ctype == "text/html":
                body = part.get_payload(decode=True).decode(errors="replace")
                urls = re.findall(r'https?://[^\s"\'<>)]+', body)
                for u in urls:
                    host = urlparse(u).hostname
                    print(u, host)
                    reasons = []
                    if  re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', host):
                        reasons.append("raw IP")
                    if "xn--" in host:
                        reasons.append("punycode")
                    if host in SHORTENERS:
                        reasons.append("shortener")
                    for brand in BRANDS:
                        reg = ".".join(host.split(".")[-2:]) #The www. drags the similarity ratio down, so real lookalikes might slip under 0.8
                        ratio = difflib.SequenceMatcher(None, reg, brand).ratio()
                        if reg in ALLOWLIST:
                            continue  # trusted domain
                        if ratio >= 0.8 and reg != brand:
                            reasons.append(f"lookalike of {brand}")
                    if reasons:
                        print(f"SUSPICIOUS {u} - {reasons}")