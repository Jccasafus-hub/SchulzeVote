import os
import json
from urllib.parse import quote
from flask import render_template, request, redirect, url_for, flash, Response, abort, session
from . import admin_bp

# === Config / helpers locais (evita import circular com app.py) ===
ADMIN_SECRET = (os.environ.get("ADMIN_SECRET", "troque-admin") or "").strip()
ELECTION_FILE = "election.json"
MAX_ADMIN_ATTEMPTS = int(os.environ.get("ADMIN_LOGIN_MAX_ATTEMPTS", "5"))  # padrão: 5

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
    return (req.args.get("secret") or req.headers.get("X-Admin-Secret") or "").strip()

def _encoded_secret(req) -> str:
    return quote(_extract_secret(req), safe="")

def _get_attempts() -> int:
    return int(session.get("admin_attempts", 0))

def _inc_attempts() -> int:
    n = _get_attempts() + 1
    session["admin_attempts"] = n
    return n

def _reset_attempts():
    session.pop("admin_attempts", None)

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
    # Bloqueia se excedeu o limite de tentativas na sessão
    if request.method == "POST" and _get_attempts() >= MAX_ADMIN_ATTEMPTS:
        flash("Limite de tentativas atingido para esta sessão do navegador. Tente novamente mais tarde.", "error")
        return redirect(url_for("admin_bp.login"))

    if request.method == "POST":
        secret = (request.form.get("secret") or "").strip()
        ok = (secret == ADMIN_SECRET)

        if ok:
            _reset_attempts()
            encoded = quote(secret, safe="")
            return redirect(url_for("admin_bp.home") + f"?secret={encoded}")

        used = _inc_attempts()
        remaining = max(0, MAX_ADMIN_ATTEMPTS - used)
        if remaining == 0:
            msg = "Chave secreta inválida. Você atingiu o limite de tentativas para esta sessão."
        else:
            msg = f"Chave secreta inválida. {remaining} tentativa(s) restante(s)."
        flash(msg, "error")
        return redirect(url_for("admin_bp.login"))

    # GET
    return render_template(
        "admin_login.html",
        max_attempts=MAX_ADMIN_ATTEMPTS,
        attempts_used=_get_attempts(),
        secret=_encoded_secret(request)
    )

# ========== Home ==========
@admin_bp.route("/")
def home():
    if not require_admin(request):
        return redirect(url_for("admin_bp.login"))
    secret_encoded = _encoded_secret(request)
    current_eid = get_current_election_id()
    return render_template("admin_home.html", secret=secret_encoded, current_eid=current_eid)

# ========== Logout (preserva secret) ==========
@admin_bp.route("/logout")
def logout():
    """
    Redireciona para o login já com ?secret=<encodado>, para facilitar voltar
    sem redigitar a chave. Zera o contador de tentativas.
    """
    _reset_attempts()
    secret_encoded = _encoded_secret(request)
    flash("Você saiu do painel administrativo.", "info")
    # Se houver secret atual, preserva no redirect
    if secret_encoded:
        return redirect(url_for("admin_bp.login") + f"?secret={secret_encoded}")
    return redirect(url_for("admin_bp.login"))

@admin_bp.route("/_hello")
def admin_hello():
    return "admin ok"
