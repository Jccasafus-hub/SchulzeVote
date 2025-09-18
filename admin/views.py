import os
import json
from pathlib import Path
from urllib.parse import quote
from flask import render_template, request, redirect, url_for, flash, Response, abort
from . import admin_bp

# === Config / helpers locais (evita import circular com app.py) ===
ADMIN_SECRET = (os.environ.get("ADMIN_SECRET", "troque-admin") or "").strip()
ELECTION_FILE = "election.json"

def require_admin(req) -> bool:
    token = (req.args.get("secret") or req.headers.get("X-Admin-Secret") or "").strip()
    return bool(ADMIN_SECRET and token == ADMIN_SECRET)

def _read_json(path: str, default):
    try:
        if not os.path.exists(path):
            return default
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def get_current_election_id() -> str:
    d = _read_json(ELECTION_FILE, {})
    return d.get("election_id", "default")

def _extract_secret(req) -> str:
    """Obtém o secret da query ou header (sem validar)."""
    return (req.args.get("secret") or req.headers.get("X-Admin-Secret") or "").strip()

# ========== Diagnóstico ==========
@admin_bp.route("/ping")
def ping():
    ok = require_admin(request)
    return Response(
        json.dumps({"ok": ok}, ensure_ascii=False),
        status=200 if ok else 403,
        mimetype="application/json"
    )

# ========== Login ==========
@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        secret = (request.form.get("secret") or "").strip()
        if secret == ADMIN_SECRET:
            encoded = quote(secret, safe="")  # evita quebrar URL com #, &, +, !
            return redirect(url_for("admin_bp.home") + f"?secret={encoded}")
        flash("Chave secreta inválida.", "error")
        return redirect(url_for("admin_bp.login"))
    return render_template("admin_login.html")

# ========== Home ==========
@admin_bp.route("/")
def home():
    if not require_admin(request):
        return redirect(url_for("admin_bp.login"))
    secret = _extract_secret(request)
    current_eid = get_current_election_id()
    return render_template("admin_home.html", secret=secret, current_eid=current_eid)

# ========== Logout ==========
@admin_bp.route("/logout")
def logout():
    # Limpeza de cache é disparada no front (base_admin.html) via postMessage('PURGE_CACHE')
    flash("Você saiu do painel administrativo.", "info")
    return redirect(url_for("admin_bp.login"))
