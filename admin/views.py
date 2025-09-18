import os
import traceback
from flask import (
    render_template, request, redirect, url_for, jsonify, flash, Response
)

# Importa o blueprint declarado em admin/__init__.py
from . import admin_bp

# --- Config local (pega do ambiente; mantém padrão caso ausente) ---
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "troque-admin")


def _has_secret(req) -> bool:
    """Valida o secret vindo da query ou header (compatível com require_admin do app.py)."""
    token = (req.args.get("secret") or req.headers.get("X-Admin-Secret") or "").strip()
    return bool(ADMIN_SECRET) and token == ADMIN_SECRET


def _secret_qs(req) -> str:
    """Retorna o secret da query (se presente)."""
    return (req.args.get("secret") or "").strip()


# ------------------ Rotas utilitárias de diagnóstico ------------------

@admin_bp.route("/_hello")
def admin_hello():
    # Diagnóstico simples: se esta rota responde, o blueprint está registrado.
    return "admin ok"


@admin_bp.route("/ping")
def admin_ping():
    ok = _has_secret(request)
    return jsonify({"ok": ok}), (200 if ok else 403)


# ------------------ Autenticação (login/logout) ------------------

@admin_bp.route("/login", methods=["GET", "POST"])
def admin_login():
    """
    Login do admin por 'secret' (chave única).
    - GET: exibe o formulário.
    - POST: valida o secret e redireciona para o painel com ?secret=...
    """
    if request.method == "POST":
        provided = (request.form.get("secret") or "").strip()
        if provided and ADMIN_SECRET and provided == ADMIN_SECRET:
            # sucesso → redireciona com o secret propagado
            return redirect(url_for("admin_bp.admin_home") + f"?secret={provided}")
        flash("Chave inválida.", "error")
        # cai para o GET e reexibe o formulário
    return render_template("admin_login.html")


@admin_bp.route("/logout")
def admin_logout():
    """
    Logout "stateless": apenas retorna para login.
    Se houver ?secret= na URL, redireciona para /admin/login?secret=... (facilita retorno).
    """
    secret = _secret_qs(request)
    if secret:
        return redirect(url_for("admin_bp.admin_login") + f"?secret={secret}")
    return redirect(url_for("admin_bp.admin_login"))


# ------------------ Painel (home) ------------------

@admin_bp.route("/")
def admin_home():
    """
    Painel inicial do admin. Requer secret via query/header.
    Tenta renderizar o template e, se falhar, mostra o traceback para corrigirmos rápido.
    (Remova o try/except depois de consertar.)
    """
    if not _has_secret(request):
        # Sem permissão → manda para login (sem secret)
        return redirect(url_for("admin_bp.admin_login"))

    try:
        return render_template("admin_home.html")
    except Exception:
        tb = traceback.format_exc()
        html = (
            "<h1>Erro ao renderizar admin_home.html</h1>"
            "<p>Tente conferir se <code>templates/admin_home.html</code> e <code>templates/base_admin.html</code> existem, "
            "e se não há erros de Jinja (tags não fechadas, variáveis inexistentes, etc.).</p>"
            "<pre style='white-space:pre-wrap; background:#111; color:#eee; padding:12px; border-radius:8px;'>"
            + tb.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            + "</pre>"
        )
        return Response(html, status=500, mimetype="text/html")
