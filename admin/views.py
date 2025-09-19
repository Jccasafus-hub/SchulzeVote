# admin/views.py
from flask import (
    render_template, request, redirect, url_for,
    flash, current_app
)
# 💡 IMPORTANTE: traga o blueprint criado em admin/__init__.py
from . import admin_bp


@admin_bp.after_request
def _no_cache(resp):
    """Evita cache nas páginas do admin."""
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

# ✅ raiz do admin → redireciona para /admin/login
@admin_bp.route("/")
def admin_root():
    return redirect(url_for("admin_bp.admin_login"))

@admin_bp.route("/_hello")
def hello():
    return "admin ok"

@admin_bp.route("/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        form_secret = (request.form.get("secret") or "").strip()
        if not form_secret:
            form_secret = (request.form.get("keep_secret") or "").strip()

        admin_secret = current_app.config.get("ADMIN_SECRET", "")
        if not form_secret:
            flash("Cole sua chave de administrador.", "error")
            return redirect(url_for("admin_bp.admin_login"))

        if form_secret == admin_secret:
            return redirect(url_for("admin_bp.admin_home", secret=form_secret))

        flash("Chave inválida.", "error")
        return redirect(url_for("admin_bp.admin_login"))

    return render_template("admin_login.html")

@admin_bp.route("/home")
def admin_home():
    secret = (request.args.get("secret") or "").strip()
    admin_secret = current_app.config.get("ADMIN_SECRET", "")
    if not secret or secret != admin_secret:
        flash("Informe sua chave de administrador para acessar o painel.", "info")
        return redirect(url_for("admin_bp.admin_login"))
    return render_template("admin_home.html")

@admin_bp.route("/logout")
def admin_logout():
    secret = (request.args.get("secret") or "").strip()
    if secret:
        return redirect(url_for("admin_bp.admin_login", secret=secret))
    return redirect(url_for("admin_bp.admin_login"))
