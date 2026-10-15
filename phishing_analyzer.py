
import sys
import html
import json
import argparse
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import re
from html.parser import HTMLParser
import ipaddress
from urllib.parse import urlparse
import hashlib

def read_eml(path):
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def clean(value, max_len=200):
    text = "" if value is None else str(value)
    text = "".join(c if c.isprintable() else "?" for c in text)
    return text[:max_len]


def sender_info(msg):
    name, addr = parseaddr(str(msg["From"]))
    _, reply = parseaddr(str(msg["Reply-To"] or ""))
    return name, addr.lower(), reply.lower()


BRANDS = ("paypal", "microsoft", "apple", "amazon", "google", "netflix")


def finding(category, points, message):
    return {"category": category, "points": points, "message": message}


def domain_of(addr):
    return addr.rsplit("@", 1)[-1]


def defang(url):
    url = re.sub(r"^http", "hxxp", url, flags=re.IGNORECASE)
    return clean(url.replace(".", "[.]"), 300)


def get_bodies(msg):
    plain, html_text = "", ""
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain":
            plain += part.get_content()
        elif ctype == "text/html":
            html_text += part.get_content()
    return plain, html_text


URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)


def urls_from_text(text):
    return [u.rstrip(".,;:!?") for u in URL_RE.findall(text)]


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self._href = None
        self._text = ""

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = ""




    def handle_data(self, data):
        if self._href is not None:
            self._text += data

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href.strip(), self._text.strip()))
            self._href = None




def links_from_html(html_text):
    parser = LinkParser()
    parser.feed(html_text)
    return parser.links


def extract_links(msg):
    plain, html_text = get_bodies(msg)
    found = {}
    for url in urls_from_text(plain):
        found[url] = ""
    for url, text in links_from_html(html_text):
        found[url] = text
    return list(found.items())



def host_of(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy"}


LEET = str.maketrans("01345", "oleas")
BRAND_DOMAINS = {"paypal": "paypal.com", "microsoft": "microsoft.com", "apple": "apple.com",
                 "amazon": "amazon.com", "google": "google.com", "netflix": "netflix.com"}


def find_brand_abuse(host):
    tokens = re.split(r"[.-]", host.translate(LEET))
    for brand, legit in BRAND_DOMAINS.items():
        if host == legit or host.endswith("." + legit):
            continue
        if any(t == brand or (len(brand) >= 6 and brand in t) for t in tokens):
            return brand
    return None


def analyze_links(links):
    out = []
    for url, text in links:
        host = host_of(url)
        if not host:
            continue
        if is_ip(host):
            out.append(finding("link", 20, f"Lien vers une adresse IP au lieu d'un nom de domaine : {defang(url)}"))
        if host in SHORTENERS:
            out.append(finding("link", 10, f"Raccourcisseur d'URL qui cache la destination réelle : {defang(url)}"))


        shown = re.fullmatch(r"(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?:/\S*)?", text, re.I)
        if shown:
            shown_host = shown.group(1).lower()
            real = host[4:] if host.startswith("www.") else host
            if not (real == shown_host or real.endswith("." + shown_host) or shown_host.endswith("." + real)):
                out.append(finding("link", 25, f"Le texte du lien affiche « {defang(shown_host)} » mais il mène à « {defang(host)} »"))
        brand = find_brand_abuse(host)
        if brand:
            out.append(finding("link", 20, f"Le domaine imite la marque « {brand} » : {defang(url)}"))
    return out


def get_attachments(msg):
    out = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        name = part.get_filename()
        if name or part.get_content_disposition() == "attachment":
            data = part.get_payload(decode=True) or b""
            out.append({"filename": name or "(sans nom)", "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest()})
    return out

DANGEROUS_EXT = {".exe", ".scr", ".bat", ".cmd", ".com", ".js", ".vbs", ".ps1", ".jar", ".msi", ".lnk", ".hta"}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png"}
MACRO_EXT = {".docm", ".xlsm", ".pptm"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".iso"}


def check_attachments(attachments):
    out = []
    for att in attachments:
        parts = att["filename"].lower().split(".")
        ext = "." + parts[-1] if len(parts) > 1 else ""
        label = clean(att["filename"])
        if ext in DANGEROUS_EXT:
            out.append(finding("attachment", 30, f"Type de pièce jointe dangereux « {clean(ext)} » : {label}"))
            if len(parts) >= 3 and "." + parts[-2] in DOC_EXT:
                out.append(finding("attachment", 25, f"Double extension qui cache le vrai type : {label}"))
        elif ext in MACRO_EXT:
            out.append(finding("attachment", 20, f"Document Office pouvant contenir des macros : {label}"))
        elif ext in ARCHIVE_EXT:
            out.append(finding("attachment", 5, f"Archive pouvant cacher un fichier malveillant : {label}"))
    return out


SCAM_WORDS = ("urgent", "immédiatement", "immediately", "dernier avertissement", "suspended",
              "suspendu", "verify your account", "vérifiez votre compte", "within 24 hours",
              "sous 24 heures", "unusual activity", "activité inhabituelle", "poursuites")


def check_content(msg):
    plain, html_text = get_bodies(msg)
    text = (str(msg["Subject"] or "") + " " + plain + " " + html_text).lower()
    found = [w for w in SCAM_WORDS if w in text]
    if found:
        return [finding("content", 10, f"Vocabulaire d'urgence ou d'arnaque : {', '.join(found)}")]
    return []


CATEGORY_CAPS = {"sender": 50, "authentication": 50, "link": 45, "attachment": 60, "content": 15}


def compute_score(findings):
    per_category = {}
    for f in findings:
        per_category[f["category"]] = per_category.get(f["category"], 0) + f["points"]
    capped = {c: min(p, CATEGORY_CAPS.get(c, 50)) for c, p in per_category.items()}
    return min(100, sum(capped.values())), capped


def check_sender(msg):
    name, addr, reply = sender_info(msg)
    domain = domain_of(addr)
    out = []
    if reply and domain_of(reply) != domain:
        out.append(finding("sender", 15, f"Reply-To différent de l'expéditeur : {clean(domain_of(reply))}"))
    for brand in BRANDS:
        if brand in name.lower() and brand not in domain:
            out.append(finding("sender", 20, f"Le nom affiché cite « {brand} » mais le domaine réel est {clean(domain)}"))
    return out


def auth_results(msg):
    header = str(msg["Authentication-Results"] or "").lower()
    results = {}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(mech + r"=(\w+)", header)
        results[mech] = m.group(1) if m else "absent"
    return results



WEIGHTS = {"spf": 15, "dkim": 15, "dmarc": 20}


def check_auth(msg):
    out = []
    for mech, result in auth_results(msg).items():
        if result in ("fail", "permerror", "temperror"):
            out.append(finding("authentication", WEIGHTS[mech], f"{mech.upper()} : {result}"))
        elif result == "softfail":
            out.append(finding("authentication", WEIGHTS[mech] // 2, f"{mech.upper()} : softfail (échec léger)"))
    return out


def verdict_for(score):
    if score >= 55:
        return "RISQUE ÉLEVÉ"
    if score >= 25:
        return "SUSPECT"
    return "RISQUE FAIBLE"


def analyze_file(path):
    msg = read_eml(path)
    links = extract_links(msg)
    attachments = get_attachments(msg)
    findings = (check_sender(msg) + check_auth(msg) + analyze_links(links)
                + check_attachments(attachments) + check_content(msg))
    score, breakdown = compute_score(findings)
    return {
        "file": clean(path),
        "from": clean(msg["From"]),
        "subject": clean(msg["Subject"]),
        "score": score,
        "verdict": verdict_for(score),
        "breakdown": breakdown,
        "findings": [{"category": f["category"], "points": f["points"],
                      "message": clean(f["message"], 300)} for f in findings],
        "auth": auth_results(msg),
        "links": [{"url": defang(u), "text": defang(t) if t else ""} for u, t in links],
        "attachments": [{"filename": clean(a["filename"]), "size": a["size"],
                         "sha256": a["sha256"]} for a in attachments],
    }


def print_report(r):
    print("=" * 64)
    print("Fichier    :", r["file"])
    print("Expéditeur :", r["from"])
    print("Objet      :", r["subject"])
    print(f"Verdict    : {r['verdict']} (score {r['score']}/100)")
    print("-" * 64)
    for f in r["findings"]:
        print(f"  [+{f['points']:>2}] {f['category']:<14} {f['message']}")
    if not r["findings"]:
        print("  Aucun indice détecté.")
    print("Score par catégorie :", " | ".join(f"{c} {p}" for c, p in r["breakdown"].items()) or "aucune")
    a = r["auth"]
    print("SPF/DKIM/DMARC :", a["spf"], "/", a["dkim"], "/", a["dmarc"])
    for link in r["links"]:
        shown = f" [texte affiché : {link['text']}]" if link["text"] else ""
        print("Lien           :", link["url"] + shown)
    for att in r["attachments"]:
        print("Pièce jointe   :", att["filename"], f"({att['size']} octets) sha256={att['sha256']}")
    print("Analyse hors ligne : aucun lien ouvert, aucune pièce jointe exécutée.")
    print("Un score faible n'est pas une preuve de sécurité.")


CSS_CLASS = {"RISQUE ÉLEVÉ": "high", "SUSPECT": "mid", "RISQUE FAIBLE": "low"}


def card_html(r):
    esc = html.escape
    rows = "".join(
        f"<tr><td>+{f['points']}</td><td>{esc(f['category'])}</td><td>{esc(f['message'])}</td></tr>"
        for f in r["findings"]) or "<tr><td colspan='3'>Aucun indice détecté.</td></tr>"
    links = "".join(f"<li>{esc(l['url'])}</li>" for l in r["links"]) or "<li>aucun</li>"
    atts = "".join(f"<li>{esc(a['filename'])} ({a['size']} octets)<br>SHA-256 : {esc(a['sha256'])}</li>"
                   for a in r["attachments"]) or "<li>aucune</li>"
    auth = r["auth"]
    return (
        f"<section class='card {CSS_CLASS[r['verdict']]}'>"
        f"<h2>{esc(r['verdict'])} · {r['score']}/100</h2>"
        f"<p><b>Fichier :</b> {esc(r['file'])}<br>"
        f"<b>Expéditeur :</b> {esc(r['from'])}<br>"
        f"<b>Objet :</b> {esc(r['subject'])}</p>"
        f"<table>{rows}</table>"
        f"<p><b>SPF / DKIM / DMARC :</b> {esc(auth['spf'])} / {esc(auth['dkim'])} / {esc(auth['dmarc'])}</p>"
        f"<p><b>Liens (désarmés) :</b></p><ul>{links}</ul>"
        f"<p><b>Pièces jointes :</b></p><ul>{atts}</ul></section>")


STYLE = """
body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;background:#f5f5f5;color:#1a1a1a}
.card{background:#fff;border:1px solid #ddd;border-left:10px solid;border-radius:8px;padding:1rem 1.25rem;margin:1.25rem 0}
.high{border-left-color:#b3261e}.mid{border-left-color:#b26a00}.low{border-left-color:#1b7f3b}
.high h2{color:#b3261e}.mid h2{color:#b26a00}.low h2{color:#1b7f3b}
h2{margin:.2rem 0 .6rem}table{border-collapse:collapse;width:100%}
td{padding:.3rem .5rem;border-top:1px solid #eee;vertical-align:top}
td:first-child{font-weight:bold;white-space:nowrap}li{word-break:break-all}.note{color:#555;font-size:.9rem}
"""


def write_html(results, path):
    ranked = sorted(results, key=lambda r: r["score"], reverse=True)
    cards = "".join(card_html(r) for r in ranked)
    page = (
        "<!DOCTYPE html><html lang='fr'><head><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        "<title>Rapport phishing-analyzer</title><style>" + STYLE + "</style></head><body>"
        "<h1>Rapport phishing-analyzer</h1>"
        "<p class='note'>Analyse hors ligne : aucun lien ouvert, aucune pièce jointe exécutée. "
        "Un score faible n'est pas une preuve de sécurité.</p>"
        + cards + "</body></html>")
    with open(path, "w", encoding="utf-8") as out:
        out.write(page)


def main():
    parser = argparse.ArgumentParser(description="Analyse hors ligne d'un ou plusieurs e-mails (.eml)")
    parser.add_argument("fichiers", nargs="+", help="un ou plusieurs fichiers .eml")
    parser.add_argument("--json", action="store_true", help="afficher le résultat au format JSON")
    parser.add_argument("--html", metavar="FICHIER", help="écrire un rapport HTML")
    args = parser.parse_args()
    results = [analyze_file(p) for p in args.fichiers]
    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        for r in results:
            print_report(r)
    if args.html:
        write_html(results, args.html)
        print("Rapport HTML écrit dans :", clean(args.html), file=sys.stderr)


if __name__ == "__main__":
    main()
