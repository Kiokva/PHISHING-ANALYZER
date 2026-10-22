#!/usr/bin/env python3
"""phishing_analyzer - triage a suspicious email (.eml) offline.

Parses headers, authentication results, links and attachments, then prints
a risk score with the reasons behind it. It never opens links, downloads
anything, or contacts the network, and it defangs links in its output.

    python3 phishing_analyzer.py suspicious.eml
    python3 phishing_analyzer.py suspicious.eml --json
"""
import argparse
import hashlib
import ipaddress
import json
import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

BRANDS = {
    "paypal": "paypal.com", "microsoft": "microsoft.com", "apple": "apple.com",
    "amazon": "amazon.com", "google": "google.com", "netflix": "netflix.com",
    "dhl": "dhl.com", "fedex": "fedex.com", "docusign": "docusign.com",
    "linkedin": "linkedin.com", "dropbox": "dropbox.com", "facebook": "facebook.com",
    "instagram": "instagram.com", "outlook": "outlook.com", "office365": "office.com",
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy"}
RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq", "top", "xyz", "icu", "click", "work", "su", "ru", "cn", "pw", "zip", "mov"}
RISKY_EXT = {"exe", "scr", "com", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "hta", "lnk",
             "jar", "msi", "iso", "img", "dll", "reg", "docm", "xlsm", "pptm", "one"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "ace"}
URGENCY = ("urgent", "immediately", "suspended", "verify your", "confirm your", "unusual activity",
           "action required", "within 24 hours", "account will be", "final notice", "password expires")
SLD = {"co", "com", "org", "net", "gov", "ac", "edu"}
LOOKALIKE = str.maketrans({"1": "l", "0": "o", "5": "s", "3": "e"})

IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
URL_RX = re.compile(r"https?://[^\s<>\"'`)\]]+", re.I)


def defang(value: str) -> str:
    return re.sub(r"^http", "hxxp", value, flags=re.I).replace(".", "[.]").replace("@", "[@]")


def base_domain(domain: str) -> str:
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in SLD and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower().strip() if "@" in address else ""


class Findings:
    def __init__(self):
        self.items = []

    def add(self, points: int, category: str, message: str):
        if any(i["message"] == message for i in self.items):
            return
        self.items.append({"points": points, "category": category, "message": message})

    @property
    def score(self) -> int:
        return min(100, sum(i["points"] for i in self.items))


class LinkParser(HTMLParser):
    """Collects (href, visible text) pairs and the visible body text."""

    def __init__(self):
        super().__init__()
        self.links, self.text = [], []
        self._href, self._label = None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href, self._label = dict(attrs).get("href"), []

    def handle_data(self, data):
        self.text.append(data)
        if self._href is not None:
            self._label.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href.strip(), " ".join("".join(self._label).split())))
            self._href = None


def check_url(url: str, shown_text: str, f: Findings):
    try:
        parsed = urlparse(url)
    except ValueError:
        return
    host = (parsed.hostname or "").lower()
    if not host:
        return
    label = defang(url)
    if shown_text:
        m = URL_RX.search(shown_text) or re.search(r"\b(?:[\w-]+\.)+[a-z]{2,}\b", shown_text, re.I)
        if m:
            shown_host = (urlparse(m.group()).hostname or m.group()).lower()
            if base_domain(shown_host) != base_domain(host):
                f.add(35, "links", f"Link text shows {defang(shown_host)} but goes to {defang(host)}")
    try:
        ipaddress.ip_address(host)
        f.add(25, "links", f"Link points at a raw IP address: {label}")
    except ValueError:
        pass
    if host in SHORTENERS:
        f.add(15, "links", f"URL shortener hides the destination: {label}")
    if "xn--" in host:
        f.add(25, "links", f"Punycode (possible lookalike characters) in {defang(host)}")
    if "@" in (parsed.netloc or ""):
        f.add(25, "links", f"Credentials-style '@' trick in URL: {label}")
    if parsed.scheme == "http":
        f.add(8, "links", f"Unencrypted http link: {label}")
    if host.rsplit(".", 1)[-1] in RISKY_TLDS:
        f.add(10, "links", f"Link uses a TLD often seen in abuse: {defang(host)}")
    if host.count(".") >= 4:
        f.add(8, "links", f"Unusually many subdomains: {defang(host)}")


def analyze(raw: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    f = Findings()
    info = {}

    # ---- sender ---------------------------------------------------
    name, addr = parseaddr(str(msg.get("From", "")))
    from_dom = domain_of(addr)
    subject = str(msg.get("Subject", ""))
    info["from"] = {"display_name": name, "address": addr}
    info["subject"] = subject

    for hdr in ("Reply-To", "Return-Path"):
        _, other = parseaddr(str(msg.get(hdr, "")))
        if other and from_dom and base_domain(domain_of(other)) != base_domain(from_dom):
            f.add(20, "sender", f"{hdr} domain ({defang(domain_of(other))}) differs from From domain ({defang(from_dom)})")
        if other:
            info[hdr.lower().replace("-", "_")] = other

    haystack = f"{name} {subject}".lower()
    flat_from = from_dom.translate(LOOKALIKE).replace("rn", "m")
    for brand, legit in BRANDS.items():
        legit_ok = from_dom == legit or from_dom.endswith("." + legit)
        if legit_ok:
            continue
        if brand in haystack:
            f.add(25, "sender", f"Mentions '{brand}' but is sent from {defang(from_dom)}")
        if brand in flat_from:
            f.add(30, "sender", f"Sender domain {defang(from_dom)} looks like a lookalike of {brand}")

    mid_dom = domain_of(str(msg.get("Message-ID", "")).strip("<> "))
    if mid_dom and from_dom and base_domain(mid_dom) != base_domain(from_dom):
        f.add(8, "sender", f"Message-ID domain ({defang(mid_dom)}) differs from From domain")

    # ---- authentication ------------------------------------------
    auth = {}
    for h in msg.get_all("Authentication-Results", []):
        for mech, result in re.findall(r"\b(spf|dkim|dmarc)=(\w+)", str(h), re.I):
            auth.setdefault(mech.lower(), result.lower())
    for h in msg.get_all("Received-SPF", []):
        m = re.match(r"\s*(\w+)", str(h))
        if m:
            auth.setdefault("spf", m.group(1).lower())
    info["authentication"] = auth
    weights = {"fail": 20, "softfail": 10, "none": 8, "permerror": 10, "temperror": 5, "neutral": 5}
    for mech in ("spf", "dkim", "dmarc"):
        res = auth.get(mech)
        if res is None:
            f.add(5, "auth", f"No {mech.upper()} result found in headers")
        elif res in weights:
            f.add(weights[res], "auth", f"{mech.upper()} result: {res}")

    # ---- received chain ------------------------------------------
    hops = []
    for h in msg.get_all("Received", []):
        text = " ".join(str(h).split())
        ips = []
        for ip in IPV4.findall(text):
            try:
                if ipaddress.ip_address(ip).is_global:
                    ips.append(ip)
            except ValueError:
                pass
        hops.append({"header": text[:160], "public_ips": ips})
    info["received_hops"] = len(hops)
    info["origin_ip"] = next((h["public_ips"][0] for h in reversed(hops) if h["public_ips"]), None)

    # ---- content --------------------------------------------------
    body_text, links = [], []
    attachments = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        fname = part.get_filename()
        if fname or part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append({"filename": fname or "(unnamed)", "type": ctype,
                                "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
        elif ctype == "text/html":
            p = LinkParser()
            p.feed(part.get_content())
            links += p.links
            body_text.append(" ".join(" ".join(p.text).split()))
        elif ctype == "text/plain":
            body_text.append(part.get_content())

    full_text = "\n".join(body_text)
    seen = {u for u, _ in links}
    links += [(u.rstrip(".,;)"), "") for u in URL_RX.findall(full_text) if u.rstrip(".,;)") not in seen]
    for u, shown in links:
        check_url(u, shown, f)
    info["links"] = [defang(u) for u in dict.fromkeys(u for u, _ in links)]

    hits = [w for w in URGENCY if w in (subject + " " + full_text).lower()]
    if hits:
        f.add(min(15, 5 * len(hits)), "content", f"Pressure/urgency language: {', '.join(hits[:4])}")

    # ---- attachments ---------------------------------------------
    for a in attachments:
        ext = a["filename"].lower().rsplit(".", 1)[-1] if "." in a["filename"] else ""
        parts = a["filename"].lower().split(".")
        if len(parts) >= 3 and parts[-1] in RISKY_EXT:
            f.add(40, "attachments", f"Double extension '{a['filename']}' disguises an executable file")
        elif ext in RISKY_EXT:
            f.add(30, "attachments", f"Risky attachment type: {a['filename']}")
        elif ext in ARCHIVE_EXT:
            f.add(10, "attachments", f"Archive attachment can hide malware: {a['filename']}")
    info["attachments"] = attachments

    findings = sorted(f.items, key=lambda i: -i["points"])
    score = f.score
    verdict = "HIGH RISK" if score >= 50 else "SUSPICIOUS" if score >= 20 else "LOW RISK"
    return {"verdict": verdict, "score": score, "findings": findings, "details": info}


def render(result: dict) -> str:
    d = result["details"]
    out = [f"VERDICT: {result['verdict']}  (score {result['score']}/100)", ""]
    out.append(f"From:    {d['from']['display_name']} <{defang(d['from']['address'])}>")
    out.append(f"Subject: {d['subject']}")
    if d.get("reply_to"):
        out.append(f"Reply-To: {defang(d['reply_to'])}")
    auth = d["authentication"]
    out.append("Auth:    " + (", ".join(f"{k.upper()}={v}" for k, v in auth.items()) or "no results found"))
    out.append(f"Hops:    {d['received_hops']}   Origin IP: {defang(d['origin_ip']) if d['origin_ip'] else 'unknown'}")
    out += ["", "WHY:"]
    out += [f"  +{i['points']:<3} [{i['category']}] {i['message']}" for i in result["findings"]] or ["  nothing suspicious found"]
    if d["links"]:
        out += ["", "LINKS (defanged):"] + [f"  {u}" for u in d["links"]]
    if d["attachments"]:
        out += ["", "ATTACHMENTS:"]
        out += [f"  {a['filename']}  {a['size']} bytes  sha256={a['sha256']}" for a in d["attachments"]]
    out += ["", "Nothing was opened or downloaded. Treat the verdict as a lead, not a final answer."]
    return "\n".join(out)


def main(argv=None):
    p = argparse.ArgumentParser(description="Offline phishing triage for .eml files.")
    p.add_argument("file", help=".eml file to analyze, or - for stdin")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    args = p.parse_args(argv)
    raw = sys.stdin.buffer.read() if args.file == "-" else open(args.file, "rb").read()
    result = analyze(raw)
    print(json.dumps(result, indent=2) if args.json else render(result))
    return 0 if result["score"] < 50 else 2


if __name__ == "__main__":
    sys.exit(main())
