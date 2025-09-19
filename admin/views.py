from flask import Blueprint, render_template, request, redirect, url_for, session, flash, Response, current_app
import json
import os

admin_bp = Blueprint(
    "admin_bp",
    __name__,
    url_prefix="/admin",
    template_folder="../templates",
    static_folder="../static",
)

def _require_admin(req):
    admin_secret = os.environ.get("ADMIN_SECRET", "troque-admin")
    token = req.args.get("secret") or req.headers.get("X-Admin-Secret")
    return bool(admin_secret and token == admin_secret)

def _mask(s):
    if not s: return ""
    return f"{s[:2]}***{s[-2:]}"

@admin_bp.route("/_hello")
def _hello():
    return "admin ok"

@admin_bp.route("/_diag")
def _diag():
    """Página de diagnóstico rápida para ver o que está acontecendo."""
    admin_secret = os.environ.get("ADMIN_SECRET", "troque-admin")
    data = {
        "has_SESSION": bool(session),
        "session_keys": list(session.keys()),
        "session_admin_auth": bool(session.get("admin_auth")),
        "query_secret_present": "secret" in request.args,
        "query_secret_len": len(request.args.get("secret", "")),
        "require_admin_with_query": _require_admin(request),
        "ADMIN_SECRET_len": len(admin_secret),
        "ADMIN_SECRET_masked": _mask(admin_secret),
        "method": request.method,
        "path": request.path,
    }
    return Response(json.dumps(data, ensure_ascii=False, indent=2), mimetype="application/json")

@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # LOG do que chegou
        form_secret = (request.form.get("secret") or "").strip()
        current_app.logger.info(f"[admin_login] POST secret_len={len(form_secret)} present={'secret' in request.form}")

        if not form_secret:
            flash("Informe sua chave de administrador.", "error")
            return redirect(url_for("admin_bp.login"))

        admin_secret = os.environ.get("ADMIN_SECRET", "troque-admin")
        if form_secret != admin_secret:
            flash("Chave inválida.", "error")
            return redirect(url_for("admin_bp.login"))

        # Autenticado
        session["admin_auth"] = True
        # Redireciona para o painel com o ?secret= na URL para evitar cache e permitir navegação
        return redirect(url_for("admin_bp.home", secret=form_secret))

    # GET
    return render_template("admin_login.html")

@admin_bp.route("/home")
def home():
    """Painel (somente se tiver admin_auth True E ?secret válido)"""
    if not session.get("admin_auth"):
        # Mesmo sem sessão, permitimos se ?secret for válido (útil em iOS c/ cookies restritos).
        if not _require_admin(request):
            return redirect(url_for("admin_bp.login"))
    # Propaga o secret (se veio na query)
    secret = request.args.get("secret", "")
    return render_template("admin_home.html", secret=secret)

@admin_bp.route("/logout")
def logout():
    secret = request.args.get("secret", "")
    session.pop("admin_auth", None)
    flash("Você saiu do painel do administrador.", "info")
    # Deixa a pessoa sair e voltar com o mesmo ?secret se quiser
    if secret:
        return redirect(url_for("admin_bp.login") + f"?secret={secret}")
    return redirect(url_for("admin_bp.login"))
