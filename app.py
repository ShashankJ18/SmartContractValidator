import os
import io
import re
import json
from flask import Flask, render_template, request, send_file, redirect, url_for, flash, jsonify
import google.generativeai as genai
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from werkzeug.utils import secure_filename
import solcx

# ===================== SOLC SETUP =====================
try:
    solcx.set_solc_version("0.8.20")
except Exception:
    solcx.install_solc("0.8.20")
    solcx.set_solc_version("0.8.20")

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "dev-secret")

# ===================== MODEL CONFIG =====================
API_KEY = "AIzaSyDLlxsxmiK0KACUEq_neAMtE102uecGHQM"
genai.configure(api_key=API_KEY)
MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")

# ===================== ASPECTS & WEIGHTS =====================
ASPECTS = {
    "Security": {
        "weight": 0.40,
        "parameters": {
            "reentrancy_protection": 20,
            "access_control": 20,
            "overflow_checks": 20,
            "tx_origin_usage": 20,
            "external_call_safety": 20,
        },
        "prompt_hint": "Focus on vulnerabilities like reentrancy, access control, integer safety, misuse of tx.origin, and safety of external calls."
    },
    "Gas Optimization": {
        "weight": 0.20,
        "parameters": {
            "loop_efficiency": 25,
            "storage_vs_memory": 25,
            "constant_usage": 25,
            "unused_code": 25,
        },
        "prompt_hint": "Identify expensive loops, storage vs memory choices, constant usage, and unused code."
    },
    "Best Practices": {
        "weight": 0.20,
        "parameters": {
            "naming_conventions": 25,
            "comment_quality": 25,
            "modifier_usage": 25,
            "event_emission": 25,
        },
        "prompt_hint": "Assess readability, naming, documentation, modifiers, and event emission for critical actions."
    },
    "General Safety": {
        "weight": 0.20,
        "parameters": {
            "fallback_function": 25,
            "upgradability_risk": 25,
            "error_handling": 25,
            "visibility_specifiers": 25,
        },
        "prompt_hint": "Look at fallback/receive functions, upgradeability risks, error handling, and visibility."
    },
}

LAST_REPORT = None
LAST_LOGS = []

# ===================== UTILS =====================
def log_add(logs, msg):
    print(msg)
    logs.append(msg)

STATUS_RE = re.compile(r"^(?P<key>[A-Za-z0-9_]+)\s*:\s*(?P<status>PASS|PARTIAL|FAIL)\s*$", re.IGNORECASE)
REASON_RE = re.compile(r"^\s*Reason\s*:\s*(?P<reason>.+)$", re.IGNORECASE)

def call_gemini(contract_code: str, aspect_name: str, parameters: dict, hint: str, logs: list) -> str:
    prompt = f"""
You are auditing a Solidity smart contract.
Aspect: {aspect_name}
Parameters to check: {list(parameters.keys())}

For each parameter, output exactly in this strict format (repeat for all parameters, in any order):
PARAM_NAME: PASS | PARTIAL | FAIL
Reason: <short explanation>

Only return that list; do not include summaries or scores.

Context for this aspect: {hint}

Contract:
{contract_code}
"""
    log_add(logs, f"🤖 Prompting Gemini for aspect: {aspect_name} ...")
    model = genai.GenerativeModel(MODEL_NAME)
    resp = model.generate_content(prompt)
    text = (resp.text or "").strip()
    log_add(logs, f"✅ Gemini responded for {aspect_name} (chars={len(text)})")
    return text

def parse_aspect(text: str, parameters: dict):
    lines = [l for l in text.splitlines() if l.strip()]
    items = []
    missing = []
    i = 0
    seen = set()
    while i < len(lines):
        m = STATUS_RE.match(lines[i].strip())
        if m:
            key = m.group("key").strip()
            status = m.group("status").upper()
            reason = ""
            if i + 1 < len(lines):
                m2 = REASON_RE.match(lines[i + 1].strip())
                if m2:
                    reason = m2.group("reason").strip()
                    i += 1
            items.append({"key": key, "status": status, "reason": reason})
            seen.add(key)
        i += 1
    for k in parameters.keys():
        if k not in seen:
            missing.append(k)
            items.append({"key": k, "status": "FAIL", "reason": "Not addressed by analysis output."})
    return items, missing

def score_aspect(items: list, parameters: dict):
    max_total = sum(parameters.values())
    earned = 0
    param_rows = []
    for it in items:
        key = it["key"]
        weight = parameters.get(key, 0)
        status = it["status"].upper()
        if status == "PASS":
            pts = weight
        elif status == "PARTIAL":
            pts = round(0.5 * weight, 2)
        else:
            pts = 0
        earned += pts
        param_rows.append({
            "key": key,
            "weight": weight,
            "status": status,
            "reason": it.get("reason", ""),
            "points": pts,
        })
    percent = round((earned / max_total) * 100.0, 2) if max_total else 0.0
    return {"raw": round(earned, 2), "max": max_total, "percent": percent, "parameters": param_rows}

# ===================== ROUTES =====================
@app.route("/", methods=["GET", "POST"])
def index():
    global LAST_REPORT, LAST_LOGS
    report = None
    LAST_LOGS = []
    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            flash("Please upload a Solidity (.sol) file.")
            return redirect(url_for("index"))
        code = f.read().decode("utf-8", errors="ignore")
        log_add(LAST_LOGS, f"📂 Received file: {f.filename}")
        log_add(LAST_LOGS, f"📄 File size: {len(code)} chars")
        log_add(LAST_LOGS, f"🔑 API key configured: {'YES' if API_KEY and API_KEY != 'YOUR_GEMINI_API_KEY' else 'NO'}")
        log_add(LAST_LOGS, f"🧠 Model: {MODEL_NAME}")
        aspect_results = {}
        for aspect_name, cfg in ASPECTS.items():
            llm_text = call_gemini(code, aspect_name, cfg["parameters"], cfg.get("prompt_hint", ""), LAST_LOGS)
            items, missing = parse_aspect(llm_text, cfg["parameters"])
            scored = score_aspect(items, cfg["parameters"])
            aspect_results[aspect_name] = {
                "llm_raw": llm_text,
                "items": items,
                "score_raw": scored["raw"],
                "score_max": scored["max"],
                "score_percent": scored["percent"],
                "parameters": scored["parameters"],
                "weight": cfg["weight"],
                "missing": missing,
            }
        overall_100_scaled = 0.0
        contributions = []
        for aspect_name, data in aspect_results.items():
            contrib = round(data["score_percent"] * data["weight"], 2)
            contributions.append({
                "aspect": aspect_name,
                "weight": data["weight"],
                "percent": data["score_percent"],
                "contribution": contrib,
            })
            overall_100_scaled += contrib
        overall_100_scaled = round(overall_100_scaled, 2)
        verdict = "✅ USE" if overall_100_scaled >= 75 else ("⚠️ NEEDS REVIEW" if overall_100_scaled >= 50 else "❌ DO NOT USE")
        report = {
            "filename": f.filename,
            "overall_score": overall_100_scaled,
            "verdict": verdict,
            "contributions": contributions,
            "aspects": aspect_results,
            "code": code,
        }
        LAST_REPORT = report
        log_add(LAST_LOGS, "✅ Analysis complete.")
        return render_template("report.html", report=report, logs="\n".join(LAST_LOGS))
    return render_template("index.html")

@app.route("/download/json", methods=["POST"]) 
def download_json():
    if not LAST_REPORT:
        return ("No report available.", 400)
    buf = io.BytesIO(json.dumps(LAST_REPORT, indent=2).encode("utf-8"))
    return send_file(buf, as_attachment=True, download_name="audit_report.json", mimetype="application/json")

@app.route("/download/pdf", methods=["POST"]) 
def download_pdf():
    if not LAST_REPORT:
        return ("No report available.", 400)
    styles = getSampleStyleSheet()
    story = []
    story.append(Paragraph("Smart Contract Audit Report", styles["Title"]))
    story.append(Paragraph(f"File: {LAST_REPORT['filename']}", styles["Normal"]))
    story.append(Paragraph(f"Overall Score: {LAST_REPORT['overall_score']} / 100", styles["Heading3"]))
    story.append(Paragraph(f"Verdict: {LAST_REPORT['verdict']}", styles["Heading3"]))
    story.append(Spacer(1, 12))
    for c in LAST_REPORT["contributions"]:
        story.append(Paragraph(f"{c['aspect']}: {c['percent']}% × weight {c['weight']} → {c['contribution']}", styles["Normal"]))
    story.append(Spacer(1, 12))
    for aspect_name, data in LAST_REPORT["aspects"].items():
        story.append(Paragraph(aspect_name, styles["Heading2"]))
        story.append(Paragraph(f"Score: {data['score_percent']}% ({data['score_raw']} / {data['score_max']})", styles["Normal"]))
        story.append(Spacer(1, 6))
        rows = [["Parameter", "Weight", "Status", "Points", "Reason"]]
        for p in data["parameters"]:
            rows.append([p["key"], p["weight"], p["status"], p["points"], p["reason"]])
        tbl = Table(rows, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#f0f0f0")),
            ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 12))
        story.append(Paragraph("Raw analysis output:", styles["Italic"]))
        story.append(Paragraph(f"<font size=9>{data['llm_raw'].replace('<','&lt;').replace('>','&gt;')}</font>", styles["Code"]))
        story.append(Spacer(1, 12))
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf)
    doc.build(story)
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name="audit_report.pdf", mimetype="application/pdf")

# ===================== NEW EDITOR + COMPILER =====================
@app.route("/editor")
def editor():
    return render_template("editor.html")

@app.route("/compile", methods=["POST"])
def compile_contract():
    try:
        data = request.json
        source_code = data.get("code", "")

        if not source_code.strip():
            return jsonify({"success": False, "error": "No Solidity code provided."})

        compiled = solcx.compile_standard(
            {
                "language": "Solidity",
                "sources": {"Contract.sol": {"content": source_code}},
                "settings": {"outputSelection": {"*": {"*": ["abi", "evm.bytecode.object"]}}},
            },
            allow_paths="."
        )

        contracts = compiled.get("contracts", {}).get("Contract.sol", {})
        output = {}
        for name, contract_data in contracts.items():
            output[name] = {
                "abi": contract_data.get("abi"),
                "bytecode": contract_data.get("evm", {}).get("bytecode", {}).get("object"),
            }

        return jsonify({
            "success": True,
            "message": "✅ Compilation Successful!",
            "contracts": output
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# ===================== MAIN =====================
if __name__ == "__main__":
    app.run(debug=True)
