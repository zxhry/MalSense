"""
MalSense - downloadable Malware Analysis Report (PDF and DOCX).
Styled like an incident-response / digital-forensics report, with the MalSense logo as a watermark.
Educational prototype: every report carries a disclaimer saying so.

Used by app.py:  report_data(scan, user) -> dict,  build_pdf(data) -> bytes,  build_docx(data) -> bytes
"""
import io
import os
import time
from datetime import datetime

from PIL import Image

from threat_intel import attack_techniques, family_of

BASE = os.path.join(os.path.dirname(__file__), "..")
IMG_DIR = os.path.join(BASE, "static", "img")
TOOL_VERSION = "MalSense v1.0 (XGBoost classifier, KronoDroid static features, VirusTotal API v3)"
DISCLAIMER = ("This report was generated automatically by MalSense, an educational prototype developed for a "
              "Final Year Project. It is intended for learning purposes and must not be used as the sole basis "
              "for legal, disciplinary or production security decisions.")

RISK_STYLE = {   # risk level -> (label, main colour, light background)
    "HIGH": ("HIGH RISK - Malware detected", "#B3261E", "#FBE3E1"),
    "MEDIUM": ("MEDIUM RISK - Suspicious, handle with care", "#8A5300", "#FDF0D9"),
    "LOW": ("LOW RISK - No malware detected", "#1E6B3A", "#E3F4E8"),
}

IR_STEPS = {
    "HIGH": ["Do not install the application. If already installed, isolate the device from networks (Wi-Fi/mobile data).",
             "Uninstall the application and preserve this report and the file hashes as evidence.",
             "Change passwords used on the device and enable two-factor authentication on critical accounts.",
             "Review SMS, call and banking activity for unauthorised actions; contact the bank if needed.",
             "Report the incident to the organisation's security team or CyberSecurity Malaysia (Cyber999)."],
    "MEDIUM": ["Do not install unless the source is trusted (official Play Store or the developer's own website).",
               "Review the dangerous permissions listed in Section 6 and deny any that the app does not need.",
               "Re-scan the file later: antivirus signatures for new threats are often added within days.",
               "Escalate to the security team if the app was received through e-mail, SMS or a messaging app."],
    "LOW": ["No malicious indicators were found. The application may be installed from a trusted source.",
            "Grant only the permissions the app genuinely needs, and keep it updated.",
            "Re-scan if the app is later obtained from a different source or behaves unexpectedly."],
}


# ----------------------------------------------------------------------------- logo variants
def _logo_variants():
    """The web logo has white text (made for a dark website). For white paper we create:
       logo_print.png     - white parts recoloured to dark navy (header logo)
       logo_watermark.png - whole logo in light grey-blue, very transparent (watermark)"""
    src = os.path.join(IMG_DIR, "MalSenseLogo.png")
    out_print = os.path.join(IMG_DIR, "logo_print.png")
    out_wm = os.path.join(IMG_DIR, "logo_watermark.png")
    if not (os.path.exists(out_print) and os.path.exists(out_wm)
            and os.path.getmtime(out_print) >= os.path.getmtime(src)):
        im = Image.open(src).convert("RGBA")
        px = im.load()
        printed = Image.new("RGBA", im.size)
        wm = Image.new("RGBA", im.size)
        pp, pw = printed.load(), wm.load()
        for y in range(im.height):
            for x in range(im.width):
                r, g, b, a = px[x, y]
                if a == 0:
                    continue
                is_white = r > 200 and g > 200 and b > 200
                pp[x, y] = (27, 28, 40, a) if is_white else (r, g, b, a)
                pw[x, y] = (61, 139, 253, int(a * 0.10))     # 10% opacity blue
        printed.save(out_print)
        wm.save(out_wm)
    return out_print, out_wm


# ----------------------------------------------------------------------------- data
def report_data(scan, user):
    """Collect everything the report needs from a saved Scan row (+ its JSON details)."""
    d = scan.details or {}
    vt = d.get("virustotal", {})
    risk = d.get("risk", "LOW")
    feats = d.get("counts", {})
    tz = time.strftime("%z")
    tz = f"UTC{tz[:3]}:{tz[3:]}" if tz else "local time"
    return {
        "report_id": f"MS-{scan.scanned_at:%Y%m%d}-{scan.scan_id:05d}",
        "generated": datetime.now().strftime("%d %B %Y, %H:%M:%S") + f" ({tz})",
        "scanned": scan.scanned_at.strftime("%d %B %Y, %H:%M:%S") + f" ({tz})",
        "analyst": f"{user.username} <{user.email}>",
        "filename": scan.filename, "file_size": scan.file_size,
        "sha256": scan.file_hash, "sha1": d.get("sha1", "-"), "md5": d.get("md5", "-"),
        "app_name": d.get("app_name") or "-", "package": scan.package_name or "-",
        "sdk": scan.sdk_version or "-", "duration": f"{scan.scan_duration or 0:.2f} seconds",
        "verdict": scan.ml_result, "confidence": scan.confidence,
        "probability": d.get("malware_probability", 0) * 100,
        "risk": risk, "risk_label": RISK_STYLE[risk][0], "reason": d.get("reason", ""),
        "action": d.get("action", ""), "steps": IR_STEPS[risk],
        "vt_status": vt.get("status", "error"), "vt_ratio": vt.get("detection_ratio", scan.vt_result or "-"),
        "vt_flagged": vt.get("flagged"), "vt_total": vt.get("engines_total"),
        "vt_label": vt.get("threat_label") or "-", "vt_link": vt.get("link", "-"),
        "vt_message": vt.get("message", ""),
        "explanation": d.get("explanation", []),
        "counts": feats,
        "dangerous": d.get("dangerous_permissions", []),
        "dangerous_text": d.get("dangerous_text", {}),
        "custom": d.get("custom_permissions", []),
        "permissions": d.get("permissions", []),
        "attack": attack_techniques(d.get("permissions") or d.get("dangerous_permissions", [])),
        "family": family_of(vt),
        "mtype": d.get("malware_type"),                   # intents + API calls - None for LOW risk / old scans
    }


def _summary(d):
    vt = (f"{d['vt_ratio']} antivirus engines on VirusTotal flagged the file"
          if d["vt_status"] == "found" else "the file was not found in the VirusTotal database")
    return (f"The Android application <b>{d['filename']}</b> ({d['app_name']}, package {d['package']}) was analysed "
            f"statically on {d['scanned']}. The machine-learning classifier labelled the sample as "
            f"<b>{d['verdict']}</b> with {d['confidence']:.1f}% confidence, and {vt}. "
            f"Overall risk was assessed as <b>{d['risk']}</b>. {d['reason']}." + _conflict(d))



def _feature_rows(d, kind):
    """Rows for the intents / API-calls tables: [name, worth a closer look?, meaning], risky ones first.
    These come from the app's manifest and code (Androguard, feature set from CICMalDroid 2020)."""
    beh = (d.get("mtype") or {}).get("behaviours") or {}
    rows = []
    for x in beh.get(kind) or []:
        if isinstance(x, str):                                    # scans saved in the older text format
            name, _, meaning = x.partition(" - ")
            rows.append([name, "-", meaning or "-"])
        else:
            m = x.get("meaning") or "-"
            rows.append([x["name"], "Yes" if x.get("risky") else "No", m[:1].upper() + m[1:]])
    return rows


def _features_blocks(d):
    """Section 6: the three kinds of static features - permissions, intents and API calls."""
    c = d["counts"]
    blocks = [
        ("p", "MalSense analyses three kinds of static features. Permissions are used by the main classifier "
              "to decide whether the sample is malicious. Intents and sensitive API calls are read from the app's "
              "manifest and code to describe <i>what</i> the app does; they do not change the verdict."),
        ("p", "<b>6.1 Permissions</b> - what the app asks Android for."),
        ("table", ["Total", "Standard", "Normal", "Dangerous", "Signature", "Custom"],
         [[str(c.get("total_perm", "-")), str(c.get("nr_permissions", "-")), str(c.get("normal", "-")),
           str(c.get("dangerous", "-")), str(c.get("signature", "-")), str(c.get("nr_custom", "-"))]]),
        ("table", ["Dangerous permission", "What it allows the app to do"],
         [[p, d["dangerous_text"].get(p, "-")] for p in d["dangerous"]] or [["None", "-"]]),
        ("p", "<b>Custom (non-standard) permissions:</b> " + (", ".join(d["custom"]) or "none"))]
    if not d.get("mtype"):
        why = ("they are only analysed when the overall risk is MEDIUM or HIGH" if d["risk"] == "LOW" else
               "this scan was saved before they were analysed - scan the sample again to include them")
        return blocks + [("p", f"<b>6.2 Intents</b> and <b>6.3 API calls</b> - not analysed: {why}.")]
    cats = ((d["mtype"].get("behaviours") or {}).get("category")) or []
    intents, apis = _feature_rows(d, "action"), _feature_rows(d, "api")
    blocks += [("p", "<b>6.2 Intents</b> - system events the app listens for and actions it asks Android to do "
                     "(found in its manifest or code). They show <i>when</i> the app springs into action."),
               ("table", ["Intent", "Closer look", "What it means"], intents or [["None found", "-", "-"]])]
    if cats:
        blocks.append(("p", "<b>Intent categories:</b> " + ", ".join(cats)))
    blocks += [("p", "<b>6.3 API calls</b> - sensitive Android functions the app's code calls. Unlike permissions, "
                     "they show what the app is actually programmed to do."),
               ("table", ["API call", "Closer look", "What it does"], apis or [["None found", "-", "-"]])]
    return blocks

def _conflict(d):
    """Extra sentence when the classifier and VirusTotal reached different conclusions."""
    ml_mal = d["verdict"] == "Malware"
    if not ml_mal and d["risk"] == "HIGH":
        return (" <b>Note:</b> the classifier and VirusTotal disagreed. Because multiple antivirus engines "
                "independently confirmed the sample as malicious, the VirusTotal result took precedence and the "
                "sample should be handled as malware. This is a false negative of the static classifier.")
    if not ml_mal and d["risk"] == "MEDIUM":
        return (" <b>Note:</b> the classifier did not detect malware, but a small number of antivirus engines "
                "flagged the sample. This may be a false positive by those engines and should be reviewed.")
    if ml_mal and d["risk"] == "MEDIUM":
        return (" <b>Note:</b> the classifier flagged the sample, but antivirus engines did not confirm it. "
                "This may indicate previously unseen malware or a false positive, and should be reviewed.")
    return ""


def _sections(d):
    """Shared content for both formats: list of (heading, [blocks]) where a block is
    ('p', text) | ('kv', [(k, v)]) | ('table', header, rows) | ('bullets', [..])."""
    c = d["counts"]
    xai_rows = [[e["label"] + (f": {e['value']}" if e["value"] not in ("yes", "no") else ""),
                 "Malware" if e["direction"] == "malware" else "Benign", f"{e['score']:+.2f}"]
                for e in d["explanation"]]
    vt_kv = [("Lookup method", "SHA-256 hash only (the file itself was not uploaded)"),
             ("Detection ratio", d["vt_ratio"] if d["vt_status"] == "found" else d["vt_status"].replace("_", " ")),
             ("Threat label", d["vt_label"]), ("Reference", d["vt_link"])]
    if d["vt_status"] != "found" and d["vt_message"]:
        vt_kv.insert(2, ("Note", d["vt_message"]))
    return [
        ("1. Report Information", [("kv", [
            ("Report ID", d["report_id"]), ("Report generated", d["generated"]),
            ("Requested by", d["analyst"]), ("Analysis tool", TOOL_VERSION),
            ("Analysis type", "Automated static analysis - the APK was read but never installed or executed"),
            ("Classification", "TLP:CLEAR - Educational use")])]),
        ("2. Executive Summary", [("p", _summary(d)),
                                  ("p", f"<b>Recommended action:</b> {d['action']}")]),
        ("3. Sample Identification (Evidence)", [("kv", [
            ("File name", d["filename"]), ("File size", d["file_size"]),
            ("SHA-256", d["sha256"]), ("SHA-1", d["sha1"]), ("MD5", d["md5"]),
            ("Application name", d["app_name"]), ("Package name", d["package"]),
            ("Minimum Android SDK", d["sdk"]), ("Time of analysis", d["scanned"]),
            ("Analysis duration", d["duration"])]),
            ("p", "<i>Evidence handling:</i> the uploaded sample was stored under a random name only for the "
                  "duration of the analysis and deleted immediately afterwards. The cryptographic hashes above "
                  "uniquely identify the sample and can be used to verify its integrity.")]),
        ("4. Detection Results", [
            ("table", ["Engine", "Result", "Detail"], [
                ["MalSense ML classifier (XGBoost)", d["verdict"],
                 f"Malware probability {d['probability']:.1f}% (decision threshold 50%)"],
                ["VirusTotal multi-engine scan",
                 d["vt_ratio"] if d["vt_status"] == "found" else d["vt_status"].replace("_", " "),
                 d["vt_label"] if d["vt_label"] != "-" else "Secondary validation"]]),
            ("kv", vt_kv)]),
        ("5. Explainable AI - Key Decision Factors", [
            ("p", "The factors below had the greatest influence on the classifier's decision for this sample, "
                  "measured with SHAP values (positive values push towards malware, negative towards benign)."),
            ("table", ["Factor", "Pushed towards", "SHAP value"], xai_rows or [["-", "-", "-"]])]),
        ("6. App Feature Analysis (Permissions, Intents, API Calls)", _features_blocks(d)),
        ("7. Threat Intelligence", [
            ("kv", [("Malware family", d["family"][0].title() or "Not identified (no VirusTotal family label)"),
                    ("Threat category", d["family"][1].title() or "-"),
                    ("Framework", "MITRE ATT&CK for Mobile (attack.mitre.org)")]),
            ("p", "Attacker techniques that the requested permissions make possible. A permission only enables a "
                  "technique - static analysis cannot prove the app actually uses it."),
            ("table", ["Technique", "Name", "Tactic", "Enabled by"],
             [[t["id"], t["name"], t["tactic"], ", ".join(t["permissions"])] for t in d["attack"]]
             or [["-", "No mapped technique", "-", "-"]])]),
        ("8. Indicators of Compromise (IOCs)", [
            ("p", "Indicators that can be used to search for this sample in other systems. "
                  + ("They should be treated as malicious." if d["risk"] == "HIGH"
                     else "They are listed for reference; the sample was not confirmed as malicious.")),
            ("table", ["Type", "Value"], [["SHA-256", d["sha256"]], ["SHA-1", d["sha1"]], ["MD5", d["md5"]],
                                          ["Android package", d["package"]], ["File name", d["filename"]]])]),
        ("9. Risk Assessment and Recommendations", [
            ("p", f"<b>Risk level: {d['risk']}.</b> {d['reason']}."), ("bullets", d["steps"])]),
        ("10. Methodology and Limitations", [("bullets", [
            "Static analysis with Androguard: permissions, components and file metadata were extracted without "
            "running the app, so behaviour that only appears at run time (e.g. downloaded code) is not observed.",
            "Classification by an XGBoost model trained on 62,509 apps from the KronoDroid dataset "
            "(test accuracy 97.4%, recall 97.3%). As with any model, false positives and false negatives are possible.",
            "Intents and sensitive API calls were extracted from the app's manifest and code with Androguard, using "
            "the feature set of the CICMalDroid 2020 dataset. They describe the app's behaviour and do not affect the "
            "verdict; they are only analysed for samples rated MEDIUM or HIGH risk.",
            "VirusTotal was queried by SHA-256 hash only. Newly created malware may not yet be known to antivirus engines.",
            "Risk levels combine both sources: 5 or more engines flagging a file is treated as confirmed malware."])]),
    ]


# ----------------------------------------------------------------------------- PDF (reportlab)
def build_pdf(d):
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.pdfgen import canvas as rl_canvas
    from reportlab.platypus import (KeepTogether, ListFlowable, ListItem, Paragraph, SimpleDocTemplate,
                                    Spacer, Table, TableStyle)

    logo_print, logo_wm = _logo_variants()
    navy, grey = colors.HexColor("#1B1C28"), colors.HexColor("#5B6475")
    label, main, light = RISK_STYLE[d["risk"]]
    W, H = A4

    ss = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=ss["Normal"], fontName="Helvetica", fontSize=9.5, leading=13.5,
                          alignment=TA_LEFT, spaceAfter=5)
    small = ParagraphStyle("small", parent=body, fontSize=8.5, leading=11)
    h1 = ParagraphStyle("h1", parent=body, fontName="Helvetica-Bold", fontSize=20, leading=24, textColor=navy)
    h2 = ParagraphStyle("h2", parent=body, fontName="Helvetica-Bold", fontSize=12, leading=16,
                        textColor=colors.HexColor("#1F3B73"), spaceBefore=12, spaceAfter=6)
    cell = ParagraphStyle("cell", parent=body, fontSize=8.8, leading=11.5, spaceAfter=0)
    cellb = ParagraphStyle("cellb", parent=cell, fontName="Helvetica-Bold")
    mono = ParagraphStyle("mono", parent=cell, fontName="Courier", fontSize=8.3)

    def esc(t):
        return str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def val(v):
        v = str(v)
        return Paragraph(esc(v), mono if (len(v) >= 32 and " " not in v) else cell)

    grid = [("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#C9CED8")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]

    def kv_table(rows):
        t = Table([[Paragraph(esc(k), cellb), val(v)] for k, v in rows], colWidths=[4.3 * cm, W - 4 * cm - 4.3 * cm])
        t.setStyle(TableStyle(grid + [("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F3F7"))]))
        return t

    def grid_table(header, rows):
        n = len(header)
        widths = {2: [5.5 * cm, None], 3: [7.6 * cm, 3.2 * cm, None], 4: [2.4 * cm, 5.6 * cm, 3.6 * cm, None]}.get(n)
        avail = W - 4 * cm
        if widths:
            widths = [w if w else avail - sum(x for x in widths if x) for w in widths]
        else:
            widths = [avail / n] * n
        data = [[Paragraph(esc(h), ParagraphStyle("th", parent=cellb, textColor=colors.white)) for h in header]]
        data += [[val(c) for c in r] for r in rows]
        t = Table(data, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle(grid + [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3B73"))]))
        return t

    story = [Paragraph("Malware Analysis Report", h1),
             Paragraph("Static analysis of an Android application package (APK)", ParagraphStyle(
                 "sub", parent=body, textColor=grey, fontSize=10.5)),
             Spacer(1, 6)]
    banner = Table([[Paragraph(f"<b>{label}</b>", ParagraphStyle("b", parent=body, fontSize=12.5, textColor=colors.HexColor(main))),
                     Paragraph(f"Report ID <b>{d['report_id']}</b><br/>ML confidence {d['confidence']:.1f}% | "
                               f"VirusTotal {esc(d['vt_ratio'])}", ParagraphStyle("b2", parent=small, alignment=2))]],
                   colWidths=[(W - 4 * cm) * 0.58, (W - 4 * cm) * 0.42])
    banner.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(light)),
                                ("LINEBEFORE", (0, 0), (0, -1), 4, colors.HexColor(main)),
                                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                ("TOPPADDING", (0, 0), (-1, -1), 9), ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
                                ("LEFTPADDING", (0, 0), (-1, -1), 10)]))
    story += [banner, Spacer(1, 4)]

    for heading, blocks in _sections(d):
        part = [Paragraph(heading, h2)]
        for b in blocks:
            if b[0] == "p":
                part.append(Paragraph(b[1].replace(" & ", " &amp; "), body))
            elif b[0] == "kv":
                part += [kv_table(b[1]), Spacer(1, 5)]
            elif b[0] == "table":
                part += [grid_table(b[1], b[2]), Spacer(1, 5)]
            elif b[0] == "bullets":
                part.append(ListFlowable([ListItem(Paragraph(esc(x), body), leftIndent=12) for x in b[1]],
                                         bulletType="bullet", start="•", leftIndent=12))
        story.append(KeepTogether(part[:3]))
        story += part[3:]
    story += [Spacer(1, 10), Paragraph(f"<b>Disclaimer.</b> {DISCLAIMER}", ParagraphStyle(
        "disc", parent=small, textColor=grey, borderColor=colors.HexColor("#C9CED8"), borderWidth=0.5,
        borderPadding=6))]

    class NumberedCanvas(rl_canvas.Canvas):               # draws header, footer, watermark, "Page x of y"
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self._pages = []

        def showPage(self):
            self._pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._pages)
            for state in self._pages:
                self.__dict__.update(state)
                self._decorate(total)
                super().showPage()
            super().save()

        def _decorate(self, total):
            wm_w = W * 0.95                                   # watermark: big faded logo, diagonal
            wm_h = wm_w * Image.open(logo_wm).height / Image.open(logo_wm).width
            self.saveState()
            self.translate(W / 2, H / 2)
            self.rotate(35)
            self.drawImage(logo_wm, -wm_w / 2, -wm_h / 2, wm_w, wm_h, mask="auto")
            self.restoreState()
            lh = 0.75 * cm                                    # header
            lw = lh * Image.open(logo_print).width / Image.open(logo_print).height
            self.drawImage(logo_print, 2 * cm, H - 1.55 * cm, lw, lh, mask="auto")
            self.setFont("Helvetica-Bold", 8.5)
            self.setFillColor(navy)
            self.drawRightString(W - 2 * cm, H - 1.1 * cm, "MALWARE ANALYSIS REPORT")
            self.setFont("Helvetica", 8)
            self.setFillColor(grey)
            self.drawRightString(W - 2 * cm, H - 1.45 * cm, f"Report ID {d['report_id']}")
            self.setStrokeColor(colors.HexColor("#1F3B73"))
            self.setLineWidth(0.8)
            self.line(2 * cm, H - 1.75 * cm, W - 2 * cm, H - 1.75 * cm)
            self.setLineWidth(0.4)                            # footer
            self.line(2 * cm, 1.5 * cm, W - 2 * cm, 1.5 * cm)
            self.drawString(2 * cm, 1.05 * cm, "TLP:CLEAR  |  Educational use  |  Generated by MalSense v1.0")
            self.drawRightString(W - 2 * cm, 1.05 * cm, f"Page {self._pageNumber} of {total}")

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=2.3 * cm,
                            bottomMargin=2 * cm, title=f"Malware Analysis Report {d['report_id']}",
                            author="MalSense", subject=f"Analysis of {d['filename']}")
    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()


# ----------------------------------------------------------------------------- DOCX (python-docx)
def _add_field(run, instr):
    """Insert a Word field such as PAGE or NUMPAGES into a run."""
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    for kind, text in (("begin", None), (None, instr), ("separate", None), (None, "1"), ("end", None)):
        if kind:
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), kind)
        elif text == instr:
            el = OxmlElement("w:instrText")
            el.set(qn("xml:space"), "preserve")
            el.text = f" {instr} "
        else:
            el = OxmlElement("w:t")
            el.text = text
        run._r.append(el)


def _make_watermark(run, image_path, width_emu):
    """Insert a picture that floats BEHIND the text, centred on the page (a watermark)."""
    from docx.oxml import parse_xml
    from docx.shared import Emu
    run.add_picture(image_path, width=Emu(width_emu))
    inline = run._r.xpath(".//wp:inline")[0]
    cx, cy = inline.extent.cx, inline.extent.cy
    graphic = inline.xpath("./a:graphic")[0]
    docpr = inline.xpath("./wp:docPr")[0]
    anchor = parse_xml(
        '<wp:anchor xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
        'distT="0" distB="0" distL="0" distR="0" simplePos="0" relativeHeight="0" behindDoc="1" '
        'locked="1" layoutInCell="1" allowOverlap="1">'
        '<wp:simplePos x="0" y="0"/>'
        '<wp:positionH relativeFrom="page"><wp:align>center</wp:align></wp:positionH>'
        '<wp:positionV relativeFrom="page"><wp:align>center</wp:align></wp:positionV>'
        f'<wp:extent cx="{cx}" cy="{cy}"/><wp:effectExtent l="0" t="0" r="0" b="0"/><wp:wrapNone/>'
        '</wp:anchor>')
    anchor.append(docpr)
    anchor.append(parse_xml('<wp:cNvGraphicFramePr xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"/>'))
    anchor.append(graphic)
    inline.getparent().replace(inline, anchor)


def build_docx(d):
    from docx import Document
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Cm, Pt, RGBColor
    import re

    logo_print, logo_wm = _logo_variants()
    label, main, light = RISK_STYLE[d["risk"]]
    rgb = lambda h: RGBColor.from_string(h.lstrip("#"))

    doc = Document()
    sec = doc.sections[0]
    sec.page_width, sec.page_height = Cm(21), Cm(29.7)
    sec.left_margin = sec.right_margin = Cm(2)
    sec.top_margin, sec.bottom_margin = Cm(2.3), Cm(2)
    st = doc.styles["Normal"]
    st.font.name, st.font.size = "Arial", Pt(9.5)
    st.element.rPr.rFonts.set(qn("w:eastAsia"), "Arial")
    st.paragraph_format.space_after = Pt(4)

    def shade(cell, hexcolor):
        tcPr = cell._tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear"); shd.set(qn("w:color"), "auto"); shd.set(qn("w:fill"), hexcolor.lstrip("#"))
        tcPr.append(shd)

    def rich(par, text, size=None, color=None):
        """Very small HTML-ish formatter: supports <b>..</b> and <i>..</i>."""
        for part in re.split(r"(<b>.*?</b>|<i>.*?</i>)", text):
            if not part:
                continue
            r = par.add_run(re.sub(r"</?[bi]>", "", part))
            r.bold = part.startswith("<b>")
            r.italic = part.startswith("<i>")
            if size: r.font.size = Pt(size)
            if color: r.font.color.rgb = rgb(color)

    def set_cell(cell, text, bold=False, color=None, mono=False, size=None):
        p = cell.paragraphs[0]
        for old in list(p.runs):                          # start from an empty cell
            old._r.getparent().remove(old._r)
        p.paragraph_format.space_after = Pt(0)
        r = p.add_run(str(text))
        r.bold, r.font.size = bold, Pt(size or (8.5 if not mono else 8))
        if mono: r.font.name = "Consolas"
        if color: r.font.color.rgb = rgb(color)

    def pad(t, tb=70, lr=110):
        """Inner cell padding so text does not touch the borders."""
        mar = OxmlElement("w:tblCellMar")
        for side, v in (("top", tb), ("left", lr), ("bottom", tb), ("right", lr)):
            e = OxmlElement(f"w:{side}"); e.set(qn("w:w"), str(v)); e.set(qn("w:type"), "dxa"); mar.append(e)
        t._tbl.tblPr.append(mar)

    def table(header, rows, widths=None, kv=False):
        t = doc.add_table(rows=0, cols=len(header) if header else 2)
        t.style = "Table Grid"
        t.autofit = False                                  # keep the column widths we set
        pad(t)
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        if header:
            cells = t.add_row().cells
            for c, h in zip(cells, header):
                set_cell(c, h, bold=True, color="#FFFFFF"); shade(c, "#1F3B73")
        for row in rows:
            cells = t.add_row().cells
            for i, (c, v) in enumerate(zip(cells, row)):
                v = str(v)
                set_cell(c, v, bold=kv and i == 0, mono=len(v) >= 32 and " " not in v)
                if kv and i == 0: shade(c, "#F1F3F7")
        if widths:
            for row in t.rows:
                for c, w in zip(row.cells, widths):
                    c.width = Cm(w)
        doc.add_paragraph().paragraph_format.space_after = Pt(2)

    # header: logo + title + report id, watermark anchored in the header (repeats on every page)
    hdr = sec.header
    hp = hdr.paragraphs[0]
    hp.add_run().add_picture(logo_print, height=Cm(0.75))
    hp.add_run("\t\tMALWARE ANALYSIS REPORT  |  " + d["report_id"]).font.size = Pt(8)
    _make_watermark(hp.add_run(), logo_wm, int(Cm(19).emu))
    fp = sec.footer.paragraphs[0]
    fr = fp.add_run("TLP:CLEAR  |  Educational use  |  Generated by MalSense v1.0\t\tPage ")
    fr.font.size = Pt(8)
    for instr, after in (("PAGE", " of "), ("NUMPAGES", "")):
        r = fp.add_run(); r.font.size = Pt(8); _add_field(r, instr)
        if after:
            fp.add_run(after).font.size = Pt(8)

    # title + risk banner
    p = doc.add_paragraph(); rich(p, "<b>Malware Analysis Report</b>", size=20, color="#1B1C28")
    p = doc.add_paragraph(); rich(p, "Static analysis of an Android application package (APK)", size=10.5, color="#5B6475")
    bt = doc.add_table(rows=1, cols=2)
    l, r = bt.rows[0].cells
    shade(l, light); shade(r, light)
    pad(bt, tb=160, lr=200)
    set_cell(l, label, bold=True, color=main, size=12.5)
    set_cell(r, f"Report ID {d['report_id']}\nML confidence {d['confidence']:.1f}% | VirusTotal {d['vt_ratio']}")
    r.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.RIGHT
    l.width, r.width = Cm(10), Cm(7)
    doc.add_paragraph()

    for heading, blocks in _sections(d):
        h = doc.add_paragraph()
        h.paragraph_format.space_before, h.paragraph_format.keep_with_next = Pt(10), True
        rich(h, f"<b>{heading}</b>", size=12, color="#1F3B73")
        for b in blocks:
            if b[0] == "p":
                rich(doc.add_paragraph(), b[1])
            elif b[0] == "kv":
                table(None, b[1], widths=[4.3, 12.7], kv=True)
            elif b[0] == "table":
                n = len(b[1])
                table(b[1], b[2], widths={2: [5.5, 11.5], 3: [7.6, 3.2, 6.2], 4: [2.4, 5.6, 3.6, 5.4]}.get(n))
            elif b[0] == "bullets":
                for x in b[1]:
                    doc.add_paragraph(x, style="List Bullet")
    p = doc.add_paragraph(); p.paragraph_format.space_before = Pt(10)
    rich(p, f"<b>Disclaimer.</b> {DISCLAIMER}", size=8.5, color="#5B6475")

    doc.core_properties.title = f"Malware Analysis Report {d['report_id']}"
    doc.core_properties.author = "MalSense"
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()