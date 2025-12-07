# ...
import os
import sqlite3
import json
import requests
from datetime import datetime
from flask import Flask, request, jsonify, g, send_from_directory
from flask_cors import CORS

# ----- Configuration -----
DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "chats.db"))
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")  # set in PowerShell: $env:OPENAI_API_KEY="sk-..."
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

# ----- Flask App (serve project files as static so index.html + assets work) -----
app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

# ----- DB helpers -----
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_msg TEXT NOT NULL,
            bot_resp TEXT NOT NULL,
            context TEXT,
            created_at TEXT NOT NULL
        );
        """)
        db.commit()
    finally:
        cur.close()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

# ----- Utility: rule-based security responder (fallback) -----
def security_advice_from_context(user_msg: str, context: dict) -> str:
    user_low = (user_msg or "").lower()
    advice_parts = []
    nmap = context.get("nmap", "") or ""
    vuln = context.get("vuln", "") or ""

    if "ai" in user_low or "generated" in user_low or "scam" in user_low or "deepfake" in user_low:
        advice_parts.append("AI-generated scams are rising. Protect yourself by: 1) Verifying sender identity through multiple channels, 2) Avoiding clicking links in unsolicited messages, 3) Using AI-detection tools for suspicious content, 4) Enabling two-factor authentication, 5) Educating yourself on common AI scam patterns like perfect grammar or urgent requests.")
    if "phishing" in user_low or "social engineering" in user_low:
        advice_parts.append("Against phishing: Never share credentials via email/SMS. Check URLs carefully. Use antivirus with phishing protection. Report suspicious messages. For AI-enhanced phishing, look for inconsistencies in tone or context.")
    if "port" in user_low or "open" in user_low or "ssh" in user_low:
        if "22/tcp" in nmap or "ssh" in nmap.lower():
            advice_parts.append("SSH (port 22) is present. Disable root login, enforce key-based auth, and update OpenSSH.")
        else:
            advice_parts.append("Review open TCP ports and restrict access via firewall and service hardening.")
    if "https" in user_low or "ssl" in user_low or "tls" in user_low:
        if "weak cipher" in vuln.lower() or "ssl/tls weak" in vuln.lower():
            advice_parts.append("Weak TLS ciphers found. Use modern ciphers and enable TLS 1.2+/1.3.")
        else:
            advice_parts.append("Ensure TLS is configured and certificates are valid.")
    if "vuln" in user_low or "vulnerability" in user_low or "fix" in user_low:
        if vuln:
            short = "\\n".join(vuln.splitlines()[:5])
            advice_parts.append(f"Vulnerabilities found (sample): {short}. Prioritise HIGH severity issues.")
        else:
            advice_parts.append("No vulnerability details provided. Run a full scan and share findings for tailored fixes.")

    if not advice_parts:
        advice_parts.append("Please provide scan output (Nmap/vuln) or describe the issue for guidance.")
    return " ".join(advice_parts)

# ----- Utility: call OpenAI Chat Completion -----
def call_openai_chat(user_msg: str, context: dict) -> str:
    if not OPENAI_API_KEY:
        return security_advice_from_context(user_msg, context)

    system_prompt = (
        "You are a cybersecurity assistant for a student project called 'H4CK3R Security Terminal'. "
        "Provide concise, practical remediation steps, explain risk levels, and avoid giving instructions that enable wrongdoing."
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Context:\n{json.dumps(context, ensure_ascii=False, indent=2)}"},
        {"role": "user", "content": user_msg}
    ]

    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": OPENAI_MODEL,
        "messages": messages,
        "max_tokens": 500,
        "temperature": 0.0
    }

    try:
        resp = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        choices = data.get("choices") or []
        if not choices:
            return security_advice_from_context(user_msg, context)
        # handle both chat-completions and legacy shapes
        message = choices[0].get("message") or {}
        reply = message.get("content") or choices[0].get("text") or ""
        return reply.strip()
    except Exception as e:
        fallback = security_advice_from_context(user_msg, context)
        return f"(AI unavailable — fallback)\n{fallback}"

# ----- Routes -----
@app.route("/", methods=["GET"])
def root():
    return send_from_directory('.', 'index.html')

@app.route("/init", methods=["POST"])
def init():
    with app.app_context():
        init_db()
    return jsonify({"status": "ok"})

@app.route("/chat", methods=["POST"])
def chat():
    payload = request.get_json(force=True, silent=True) or {}
    user_msg = payload.get("message", "")
    context = payload.get("context", {}) or {}
    reply = call_openai_chat(user_msg, context)

    # save to DB
    try:
        db = get_db()
        cur = db.cursor()
        cur.execute(
            "INSERT INTO chats (user_msg, bot_resp, context, created_at) VALUES (?, ?, ?, ?)",
            (user_msg, reply, json.dumps(context, ensure_ascii=False), datetime.utcnow().isoformat())
        )
        db.commit()
        cur.close()
    except Exception:
        pass

    return jsonify({"reply": reply})

@app.route("/history", methods=["GET"])
def history():
    limit = int(request.args.get("limit", 50))
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, user_msg, bot_resp, context, created_at FROM chats ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    result = []
    for r in rows:
        ctx = {}
        try:
            ctx = json.loads(r["context"]) if r["context"] else {}
        except Exception:
            ctx = {}
        result.append({
            "id": r["id"],
            "user_msg": r["user_msg"],
            "bot_resp": r["bot_resp"],
            "context": ctx,
            "created_at": r["created_at"]
        })
    cur.close()
    return jsonify(result)

# ----- New Tool Routes -----

@app.route("/ai-scam-analyze", methods=["POST"])
def ai_scam_analyze():
    payload = request.get_json(force=True, silent=True) or {}
    text = payload.get("text", "").strip()

    if not text:
        return jsonify({"error": "No text provided"}), 400

    # AI scam detection patterns
    ai_scam_patterns = [
        r"urgent.*action.*required",
        r"account.*suspended",
        r"verify.*identity.*immediately",
        r"limited.*time.*offer",
        r"congratulations.*winner",
        r"perfect.*grammar.*no.*errors",
        r"too.*good.*true",
        r"click.*here.*immediately"
    ]

    import re
    risk_score = 0
    detected_patterns = []

    for pattern in ai_scam_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            risk_score += 20
            detected_patterns.append(pattern)

    # Check for AI-like characteristics
    if len(text) > 200 and not ('?' in text or '!' in text):
        risk_score += 15
        detected_patterns.append('long text without punctuation')

    result = {
        "risk_score": risk_score,
        "detected_patterns": detected_patterns[:3],  # Limit to top 3
        "risk_level": "HIGH" if risk_score > 60 else "MEDIUM" if risk_score > 30 else "LOW",
        "recommendation": "Be extremely cautious!" if risk_score > 60 else "Verify before acting." if risk_score > 30 else "Appears safe, but stay vigilant."
    }

    return jsonify(result)

@app.route("/social-engineering-quiz", methods=["GET"])
def get_quiz_questions():
    quiz_data = [
        {
            "question": "What is the most common social engineering tactic?",
            "options": ["Phishing emails", "Physical break-ins", "SQL injection", "Buffer overflow"],
            "correct": 0,
            "explanation": "Phishing emails are the most common social engineering attack, tricking users into revealing sensitive information."
        },
        {
            "question": "Which of these is NOT a sign of a social engineering attack?",
            "options": ["Urgent requests for information", "Requests for help from 'IT support'", "Official-looking emails with logos", "Regular system updates"],
            "correct": 3,
            "explanation": "Regular system updates are normal and expected, unlike urgent or unsolicited requests."
        },
        {
            "question": "What should you do if someone calls claiming to be from tech support?",
            "options": ["Give them remote access immediately", "Hang up and call back using official numbers", "Share your password to 'verify'", "Click any links they send"],
            "correct": 1,
            "explanation": "Always verify by calling back using official contact numbers, never give access or share credentials over unsolicited calls."
        },
        {
            "question": "Which tactic involves creating a sense of urgency to manipulate victims?",
            "options": ["Baiting", "Pretexting", "Scarcity principle", "Tailgating"],
            "correct": 2,
            "explanation": "The scarcity principle creates urgency by suggesting limited time or availability to pressure quick decisions."
        },
        {
            "question": "What is 'pretexting' in social engineering?",
            "options": ["Using fake websites", "Creating false identities to gain information", "Sending mass emails", "Physical intrusion"],
            "correct": 1,
            "explanation": "Pretexting involves creating a fabricated scenario or false identity to obtain confidential information."
        }
    ]
    return jsonify(quiz_data)

@app.route("/url-deep-analyze", methods=["POST"])
def url_deep_analyze():
    payload = request.get_json(force=True, silent=True) or {}
    url = payload.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    import random

    # Simulate deep URL analysis (in real app, would use APIs like VirusTotal, WHOIS, etc.)
    analysis = {
        "domain": url.replace("https://", "").replace("http://", "").split('/')[0],
        "ssl_valid": url.startswith("https://"),
        "domain_age_days": random.randint(30, 3650),  # Random age between 1 month and 10 years
        "reputation_score": "Suspicious" if random.random() > 0.8 else "Good",
        "redirect_count": random.randint(0, 3),
        "threat_level": "High" if random.random() > 0.9 else "Low",
        "whois_privacy": random.choice([True, False]),
        "ip_geolocation": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
    }

    analysis["domain_age_years"] = analysis["domain_age_days"] // 365
    analysis["domain_age_remaining_days"] = analysis["domain_age_days"] % 365

    risk_factors = []
    if not analysis["ssl_valid"]:
        risk_factors.append("Missing SSL certificate")
    if analysis["domain_age_days"] < 90:
        risk_factors.append("Very new domain")
    if analysis["reputation_score"] == "Suspicious":
        risk_factors.append("Poor domain reputation")
    if analysis["threat_level"] == "High":
        risk_factors.append("High threat intelligence score")
    if analysis["redirect_count"] > 2:
        risk_factors.append("Excessive redirects")

    result = {
        "analysis": analysis,
        "risk_factors": risk_factors,
        "overall_risk": "HIGH" if len(risk_factors) > 2 else "MEDIUM" if len(risk_factors) > 0 else "LOW",
        "recommendation": "Exercise extreme caution!" if len(risk_factors) > 2 else "Verify manually before proceeding." if len(risk_factors) > 0 else "Appears safe."
    }

    return jsonify(result)

@app.route("/email-header-inspect", methods=["POST"])
def email_header_inspect():
    payload = request.get_json(force=True, silent=True) or {}
    headers = payload.get("headers", "").strip()

    if not headers:
        return jsonify({"error": "No email headers provided"}), 400

    # Analyze email headers for spoofing
    header_lines = headers.split('\n')
    analysis = {
        "from_address": "",
        "received_count": 0,
        "spf_result": "Not found",
        "dkim_result": "Not found",
        "dmarc_result": "Not found",
        "suspicious_indicators": []
    }

    for line in header_lines:
        line_lower = line.lower()
        if line_lower.startswith('from:'):
            analysis["from_address"] = line.split(':', 1)[1].strip()
        elif line_lower.startswith('received:'):
            analysis["received_count"] += 1
        elif 'spf=' in line_lower:
            analysis["spf_result"] = "Pass" if "pass" in line_lower else "Fail"
        elif 'dkim=' in line_lower:
            analysis["dkim_result"] = "Pass" if "pass" in line_lower else "Fail"
        elif 'dmarc=' in line_lower:
            analysis["dmarc_result"] = "Pass" if "pass" in line_lower else "Fail"

    # Check for suspicious patterns
    if analysis["received_count"] > 5:
        analysis["suspicious_indicators"].append("Too many received headers (possible email forwarding abuse)")

    if analysis["spf_result"] == "Fail":
        analysis["suspicious_indicators"].append("SPF check failed")

    if analysis["dkim_result"] == "Fail":
        analysis["suspicious_indicators"].append("DKIM check failed")

    if analysis["dmarc_result"] == "Fail":
        analysis["suspicious_indicators"].append("DMARC check failed")

    # Check for common spoofing patterns
    if "@gmail.com" in analysis["from_address"] and analysis["received_count"] < 2:
        analysis["suspicious_indicators"].append("Suspicious Gmail routing")

    result = {
        "analysis": analysis,
        "is_spoofed": len(analysis["suspicious_indicators"]) > 0,
        "confidence": "HIGH" if len(analysis["suspicious_indicators"]) > 2 else "MEDIUM" if len(analysis["suspicious_indicators"]) > 0 else "LOW",
        "recommendation": "Do not trust this email!" if len(analysis["suspicious_indicators"]) > 0 else "Headers appear legitimate."
    }

    return jsonify(result)

# ----- Main -----
if __name__ == "__main__":
    with app.app_context():
        init_db()
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
# ...existing code...
