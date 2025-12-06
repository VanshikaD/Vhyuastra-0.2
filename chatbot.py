# ...existing code...
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

# ----- Main -----
if __name__ == "__main__":
    with app.app_context():
        init_db()
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
# ...existing code...
