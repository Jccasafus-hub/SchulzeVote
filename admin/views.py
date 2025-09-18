import os
from flask import render_template, request, redirect, url_for, flash
from . import admin_bp

# Lê o segredo do ambiente (mantém compatibilidade com seu app.py)
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "troque-admin")

def require_admin(req):
    """
    Compatível com o seu mecanismo atual: aceita ?secret=... ou header X-Admin-Secret
    """
    token = req.args.get("secret") or req.headers.get("X-Admin-Secret")
    return bool(ADMIN_SECRET and token == ADMIN_SECRET)

# ========= Login =========
@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        secret = (request.form.get("secret") or "").strip()
        if secret == ADMIN_SECRET:
            # Redireciona já com o secret na query (mantém compat com require_admin existente)
            return redirect(url_for("admin_bp.home") + f"?secret={secret}")
        flash("Chave secreta inválida.", "error")
        return redirect(url_for("admin_bp.login"))
    return render_template("admin_login.html")

# ========= Home =========
@admin_bp.route("/")
def home():
    # Caso não tenha ?secret=, manda pro login
    if not require_admin(request):
        return redirect(url_for("admin_bp.login"))
    return render_template("admin_home.html")

# ========= Logout =========
@admin_bp.route("/logout")
def logout():
    # A limpeza de cache do SW é feita no front (admin_home.html) via postMessage('PURGE_CACHE')
    flash("Você saiu do painel administrativo.", "info")
    return redirect(url_for("admin_bp.login"))
