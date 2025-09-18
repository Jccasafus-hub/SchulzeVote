from flask import render_template, request, redirect, url_for, flash, abort
from urllib.parse import quote
from . import admin_bp
from app import require_admin, ADMIN_SECRET, audit_admin, get_current_election_id
from datetime import datetime


# ================== Rota de login ==================
@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        secret = (request.form.get("secret") or "").strip()
        ok = (secret == ADMIN_SECRET)
        audit_admin(
            get_current_election_id(),
            "LOGIN_ATTEMPT",
            f"ok={ok}",
            request.remote_addr or "-"
        )
        if ok:
            encoded = quote(secret, safe="")  # encoda caracteres especiais
            return redirect(url_for("admin_bp.home") + f"?secret={encoded}")
        else:
            flash("Chave secreta inválida.", "error")
            return redirect(url_for("admin_bp.login"))

    return render_template("admin_login.html")


# ================== Rota Home (painel admin) ==================
@admin_bp.route("/")
def home():
    if not require_admin(request):
        abort(403)
    return render_template("admin_home.html")


# ================== Rota de teste ==================
@admin_bp.route("/ping")
def ping():
    if not require_admin(request):
        abort(403)
    return {"ok": True, "ts": datetime.utcnow().isoformat() + "Z"}
