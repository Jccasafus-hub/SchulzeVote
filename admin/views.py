import os
import json
from flask import render_template, request, redirect, url_for, flash, Response, current_app
from . import admin_bp

# Lê o segredo do ambiente (compatível com app.py)
ADMIN_SECRET = (os.environ.get("ADMIN_SECRET", "troque-admin") or "").strip()

def require_admin(req):
    """
    Verifica o token vindo por query (?secret=...) ou header (X-Admin-Secret).
    Mantém compatibilidade com o require_admin do app principal.
    """
    token = (req.args.get("secret") or req.headers.get("X-Admin-Secret") or "").strip()
    return bool(ADMIN_SECRET and token == ADMIN_SECRET)

# ========== Diagnóstico ==========
@admin_bp.route("/ping")
def ping():
    """
    Endpoint de verificação simples:
    - Retorna {"ok": true} se o secret fornecido (query/header) estiver correto.
    - Útil para depurar sem depender de templates.
    """
    ok = require_admin(request)
    return Response(
        json.dumps({"ok": ok}, ensure_ascii=False),
        status=200 if ok else 403,
        mimetype="application/json"
    )

# ========== Login ==========
@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Tela de login do Admin. No POST, valida o secret e redireciona para /admin
    já propagando ?secret=... na URL (para rotas admin que dependem do query).
    Mostra mensagens flash em caso de erro.
    """
    if request.method == "POST":
        secret = (request.form.get("secret") or "").strip()
        ok = (secret == ADMIN_SECRET)

        # Log básico da tentativa (sem revelar o segredo)
        try:
            current_app.logger.info("ADMIN login attempt ip=%s ok=%s", request.remote_addr, ok)
        except Exception:
            pass

        if ok:
            # Redireciona para a home com ?secret=... para que links internos funcionem
            return redirect(url_for("admin_bp.home") + f"?secret={secret}")

        flash("Chave secreta inválida.", "error")
        return redirect(url_for("admin_bp.login"))

    return render_template("admin_login.html")

# ========== Home ==========
@admin_bp.route("/")
def home():
    """
    Página inicial do painel admin. Exige secret válido (via query/header).
    Se não houver, redireciona para a página de login.
    """
    if not require_admin(request):
        return redirect(url_for("admin_bp.login"))
    return render_template("admin_home.html")

# ========== Logout ==========
@admin_bp.route("/logout")
def logout():
    """
    Logout "estateless": apenas redireciona ao login.
    A limpeza de cache do PWA é iniciada no front (admin_home.html) via postMessage('PURGE_CACHE').
    """
    flash("Você saiu do painel administrativo.", "info")
    return redirect(url_for("admin_bp.login"))
