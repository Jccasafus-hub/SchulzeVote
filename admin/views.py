import os
import traceback
from flask import render_template, request, redirect, url_for, jsonify, flash, Response, make_response

from . import admin_bp

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "troque-admin")


def _has_secret(req) -> bool:
    token = (req.args.get("secret") or req.headers.get("X-Admin-Secret") or "").strip()
    return bool(ADMIN_SECRET) and token == ADMIN_SECRET


def _no_cache(resp):
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


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
    - Falha: redireciona para /admin/login preservando secret via campo oculto 'keep_secret'
    """
    if request.method == "POST":
        provided = (request.form.get("secret") or "").strip()
        keep     = (request.form.get("keep_secret") or request.args.get("secret") or "").strip()

        if provided and ADMIN_SECRET and provided == ADMIN_SECRET:
            # sucesso: leva ao painel com o secret digitado
            return redirect(url_for("admin_bp.admin_home") + f"?secret={provided}")

        # falha: mantém o secret que estava na URL (ou no hidden) para não perder o contexto
        flash("Chave inválida.", "error")
        if keep:
            return redirect(url_for("admin_bp.admin_login", secret=keep))
        return redirect(url_for("admin_bp.admin_login"))

    # GET
    try:
        resp = make_response(render_template("admin_login.html"))
        return _no_cache(resp)
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
        resp = make_response(Response(html, status=500, mimetype="text/html"))
        return _no_cache(resp)


@admin_bp.route("/logout")
def admin_logout():
    keep = (request.args.get("secret") or "").strip()
    if keep:
        return redirect(url_for("admin_bp.admin_login", secret=keep))
    return redirect(url_for("admin_bp.admin_login"))


@admin_bp.route("/")
def admin_home():
    if not _has_secret(request):
        return redirect(url_for("admin_bp.admin_login"))
    resp = make_response(render_template("admin_home.html"))
    return _no_cache(resp)
