from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
import os

admin_bp = Blueprint(
    "admin_bp",
    __name__,
    url_prefix="/admin",
    template_folder="../templates",
    static_folder="../static",
)

def _get_admin_secret():
    # prioriza app.config; fallback para env; fallback legado
    return current_app.config.get("ADMIN_SECRET") or os.environ.get("ADMIN_SECRET") or "troque-admin"

def _qparam(name, default=""):
    v = request.args.get(name)
    return v if v is not None else default

@admin_bp.route("/_hello")
def admin_hello():
    return "admin ok"

@admin_bp.route("/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        # onde o secret pode vir:
        form_secret = (request.form.get("secret") or "").strip()
        keep_secret = (request.form.get("keep_secret") or "").strip()
        qs_secret   = (_qparam("secret") or "").strip()

        token = form_secret or keep_secret or qs_secret
        if not token:
            flash("Informe a sua chave de administrador.", "error")
            return render_template("admin_login.html")

        expected = _get_admin_secret()
        if token != expected:
            flash("Chave inválida.", "error")
            # mantém o que o usuário digitou para ele tentar de novo
            return render_template("admin_login.html")

        # sucesso → redireciona com ?secret= para o painel
        return redirect(url_for("admin_bp.admin_home", secret=token))

    # GET
    return render_template("admin_login.html")

@admin_bp.route("/home")
def admin_home():
    # exige que venha ?secret= válido
    token = (_qparam("secret") or "").strip()
    if token != _get_admin_secret():
        flash("Acesso negado. Informe sua chave de administrador.", "error")
        return redirect(url_for("admin_bp.admin_login"))
    return render_template("admin_home.html")

@admin_bp.route("/logout")
def admin_logout():
    # logout “estático”; só redireciona de volta para o login
    # se vier ?secret=, preserva para facilitar retorno
    token = (_qparam("secret") or "").strip()
    if token:
        return redirect(url_for("admin_bp.admin_login", secret=token))
    return redirect(url_for("admin_bp.admin_login"))
