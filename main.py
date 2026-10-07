import email
import hashlib
import os
import re
import difflib
from urllib.parse import urlparse
from email.utils import parseaddr

BRANDS = {
    "paypal.com", "google.com", "microsoft.com", "apple.com",
    "amazon.com", "netflix.com", "facebook.com", "instagram.com",
    "outlook.com", "bankofamerica.com",
}

ALLOWLIST = {
    "google.com", "googleapis.com", "gstatic.com", "googletagmanager.com",
    "microsoft.com", "apple.com", "cloudflare.com", "w3.org",
}

def header_domain(header):
    if not header:
        return None
    return parseaddr(header)[1].split('@')[-1].lower()

def load_shorteners(filename="shortener"):
    with open(filename) as f:
        return {
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        }

def analyze_headers(msg):
    header_reasons = []
    # 3 sender headers
    from_hdr = msg["FROM"]
    reply_to = msg["Reply-To"]
    return_path = msg["Return-Path"]
    from_dom = header_domain(from_hdr)
    reply_dom = header_domain(reply_to)
    rp_dom = header_domain(return_path)
    if from_dom and reply_dom and from_dom != reply_dom:
        header_reasons.append((f"Reply-To domain ({reply_dom}) != From ({from_dom})", 1.5))

    # Return-Path differs from From
    if rp_dom and from_dom and rp_dom != from_dom:
        header_reasons.append((f"Return-Path domain ({rp_dom}) != From ({from_dom})", 1.5))

    # Authentication results
    auth = (msg["Authentication-Results"] or "").lower()
    weights = {"spf": 2.0, "dkim": 2.0, "dmarc": 2.5}
    for mech in ("spf", "dkim", "dmarc"):
        if f"{mech}=fail" in auth:
            header_reasons.append((f"{mech.upper()} failed", weights[mech]))
    return header_reasons

def analyze_url(u, shorteners):
    host = urlparse(u).hostname
    if host is None:
        return []
    reasons = []
    if re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', host):
        reasons.append(("raw IP", 3.0))
    if "xn--" in host:
        reasons.append(("punycode", 2.5))
    if host in shorteners:
        reasons.append(("shortener", 1.0))
    for brand in BRANDS:
        reg = ".".join(
            host.split(".")[-2:])  # The www. drags the similarity ratio down, so real lookalikes might slip under 0.8
        ratio = difflib.SequenceMatcher(None, reg, brand).ratio()
        if reg in ALLOWLIST:
            continue  # trusted domain
        if ratio >= 0.8 and reg != brand:
            reasons.append((f"lookalike of {brand}", 3.0))
    return reasons

def hash_attachment(part):
    data = part.get_payload(decode=True) or b""
    return hashlib.sha256(data).hexdigest()

def extract_urls(body):
    return re.findall(r'https?://[^\s"\'<>)]+', body)

def analyze_email(filepath,shorteners):
    with open(filepath) as f:
        msg = email.message_from_file(f)
    print(f"Analyzing {filepath}")

    all_reasons = []
    seen_urls = set()
    all_reasons += analyze_headers(msg)

    for part in msg.walk():
        fname = part.get_filename()
        ctype = part.get_content_type()

        if fname:
            print(f"ATTACHMENT {fname} -> {hash_attachment(part)}")
        elif ctype in ("text/plain", "text/html"):
            body = part.get_payload(decode=True).decode(errors="replace")
            for u in extract_urls(body):
                if u not in seen_urls:
                    seen_urls.add(u)
                    all_reasons += analyze_url(u, shorteners)

    score = sum(weight for reason, weight in all_reasons)
    verdict_reasons = [r for r, w in all_reasons]
    if score >= 5:
        print(f"{score} - LIKELY PHISHING {verdict_reasons}")
    elif score >= 2.5:
        print(f"{score} - SUSPICIOUS {verdict_reasons}")
    else:
        print(f"{score} - CLEAN {verdict_reasons}")

def main():
    shorteners = load_shorteners()
    print(len(shorteners), "shorteners loaded")
    for file in os.listdir("."):
        if file.lower().endswith(".eml"):
            analyze_email(file, shorteners)

if __name__ == "__main__":
    main()