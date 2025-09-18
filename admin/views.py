import os
import traceback
from flask import render_template, request, redirect, url_for, jsonify, flash, Response

from . import admin_bp

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "troque-admin")


def _has_secret(req) -> bool:
    token = (req.args.get("secret") or req.headers.get("X-Admin-Secret") or "").strip()
    return bool(ADMIN_SECRET) and token == ADMIN_SECRET


def _secret_qs(req) -> str:
    return (req.args.get("secret") or "").strip()


@admin_bp.route("/_hello")
def admin_hello():
    return "admin ok"


@admin_bp.route("/ping")
def admin_ping():
    ok = _has_secret(request)
    return jsonify({"ok": ok}), (200 if ok else 403)


@admin_bp.route("/login", methods=["GET", "POST"])
def admin_login():
    """
    Login do admin via 'secret'.
    - Sucesso: redireciona para /admin/?secret=PROVIDED
    - Falha: redireciona de volta para /admin/login preservando ?secret (se existir) para não “sumir” da URL
    """
    if request.method == "POST":
        provided = (request.form.get("secret") or "").strip()
        if provided and ADMIN_SECRET and provided == ADMIN_SECRET:
            return redirect(url_for("admin_bp.admin_home") + f"?secret={provided}")

        # Falhou → preserva ?secret que já estava na URL para não perder o contexto
        keep = _secret_qs(request)
        flash("Chave inválida.", "error")
        if keep:
            return redirect(url_for("admin_bp.admin_login", secret=keep))
        return redirect(url_for("admin_bp.admin_login"))

    # GET: renderiza o template; se houver erro de template, exibe traceback na tela para depurar rápido
    try:
        return render_template("admin_login.html")
    except Exception:
        tb = traceback.format_exc()
        html = (
            "<h1>Erro ao renderizar <code>admin_login.html</code></h1>"
            "<p>Confira se <code>templates/admin_login.html</code> e <code>templates/base_admin.html</code> existem "
            "e se não há erros de Jinja.</p>"
            "<pre style='white-space:pre-wrap; background:#111; color:#eee; padding:12px; border-radius:8px;'>"
            + tb.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            + "</pre>"
        )
        return Response(html, status=500, mimetype="text/html")


@admin_bp.route("/logout")
def admin_logout():
    """
    Logout “stateless”: só redireciona para o login.
    Se houver ?secret= na URL, mantém esse parâmetro no destino, para facilitar o retorno rápido.
    """
    keep = _secret_qs(request)
    if keep:
        return redirect(url_for("admin_bp.admin_login", secret=keep))
    return redirect(url_for("admin_bp.admin_login"))


@admin_bp.route("/")
def admin_home():
    """
    Painel inicial do admin. Requer secret via query/header.
    """
    if not _has_secret(request):
        return redirect(url_for("admin_bp.admin_login"))
    return render_template("admin_home.html")
