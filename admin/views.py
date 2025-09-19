# admin/views.py
from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, current_app, make_response
)

# Este blueprint é criado em admin/__init__.py (admin_bp). Aqui só definimos as rotas.

@admin_bp.after_request
def _no_cache(resp):
    """Garante que páginas do admin não fiquem em cache (evita recarrego estranho)."""
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

@admin_bp.route("/_hello")
def hello():
    return "admin ok"

@admin_bp.route("/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        form_secret = (request.form.get("secret") or "").strip()
        # fallback: se houver keep_secret (campo oculto), usa se o principal vier vazio
        if not form_secret:
            form_secret = (request.form.get("keep_secret") or "").strip()

        admin_secret = current_app.config.get("ADMIN_SECRET", "")
        if not form_secret:
            flash("Cole sua chave de administrador.", "error")
            return redirect(url_for("admin_bp.admin_login"))

        if form_secret == admin_secret:
            # Redireciona já com ?secret= para as rotas do app principal (que exigem require_admin)
            return redirect(url_for("admin_bp.admin_home", secret=form_secret))

        flash("Chave inválida.", "error")
        return redirect(url_for("admin_bp.admin_login"))

    # GET
    return render_template("admin_login.html")

@admin_bp.route("/home")
def admin_home():
    """Painel do administrador. Exige ?secret= válido para que os atalhos funcionem."""
    secret = (request.args.get("secret") or "").strip()
    admin_secret = current_app.config.get("ADMIN_SECRET", "")
    if not secret or secret != admin_secret:
        # Sem secret válido, volta ao login (não mostramos erro 403 para não confundir).
        flash("Informe sua chave de administrador para acessar o painel.", "info")
        return redirect(url_for("admin_bp.admin_login"))
    return render_template("admin_home.html")

@admin_bp.route("/logout")
def admin_logout():
    """Sai e redireciona para o login. Se veio com ?secret=, preservamos na URL (fluxo rapidinho)."""
    secret = (request.args.get("secret") or "").strip()
    if secret:
        return redirect(url_for("admin_bp.admin_login", secret=secret))
    return redirect(url_for("admin_bp.admin_login"))
