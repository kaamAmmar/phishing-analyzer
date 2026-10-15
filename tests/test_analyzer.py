from pathlib import Path

from phishing_analyzer import (analyze_file, clean, compute_score,
                               defang, find_brand_abuse, write_html)

SAMPLES = Path(__file__).parent.parent / "samples"


def run(name):
    return analyze_file(str(SAMPLES / name))


def test_legit_email_has_no_findings():
    r = run("legit.eml")
    assert r["score"] == 0
    assert r["verdict"] == "RISQUE FAIBLE"
    assert r["findings"] == []


def test_phishing_is_high_risk():
    r = run("phishing_simple.eml")
    assert r["score"] == 100
    assert r["verdict"] == "RISQUE ÉLEVÉ"


def test_newsletter_is_suspicious_but_not_high():
    r = run("suspicious_newsletter.eml")
    assert r["verdict"] == "SUSPECT"
    assert r["score"] == 25


def test_fake_invoice_attachment_is_detected():
    r = run("malicious_attachment.eml")
    messages = " ".join(f["message"] for f in r["findings"])
    assert "Double extension" in messages
    att = r["attachments"][0]
    assert att["filename"] == "Facture_8841.pdf.exe"
    assert att["sha256"] == "dd7c7f3f00ebca882b8f76d1e5454bf5f53aac2c9e75094388c4fd6ff5a57285"


def test_links_are_defanged_in_results():
    urls = [link["url"] for link in run("phishing_simple.eml")["links"]]
    assert urls
    assert all(u.startswith("hxxp") for u in urls)
    assert not any("http://" in u or "https://" in u for u in urls)


def test_defang_breaks_the_link():
    assert defang("http://paypa1-secure.example/login") == "hxxp://paypa1-secure[.]example/login"


def test_brand_imitation_but_not_the_real_site():
    assert find_brand_abuse("paypa1-secure.example") == "paypal"
    assert find_brand_abuse("www.paypal.com") is None


def test_category_cap_limits_the_score():
    findings = [{"category": "link", "points": 30, "message": "a"},
                {"category": "link", "points": 30, "message": "b"}]
    score, breakdown = compute_score(findings)
    assert breakdown["link"] == 45
    assert score == 45


def test_clean_removes_control_characters():
    assert "\x1b" not in clean("Salut\x1b[31m rouge\nligne")


def test_hostile_email_cannot_inject_html(tmp_path):
    eml = tmp_path / "hostile.eml"
    eml.write_text(
        'From: "<script>alert(1)</script>" <x@evil.example>\n'
        "Subject: <img src=x onerror=alert(2)> hello\n"
        "Content-Type: text/plain\n\n"
        'http://evil.example/"><script>alert(3)</script>\n',
        encoding="utf-8")
    report = tmp_path / "rapport.html"
    write_html([analyze_file(str(eml))], str(report))
    page = report.read_text(encoding="utf-8")
    assert "<script" not in page
    assert "<img" not in page
    assert "&lt;script&gt;" in page
