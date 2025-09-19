from flask import (
    current_app, render_template, request, redirect, url_for, abort, flash
)
from . import admin_bp  # pega o blueprint já criado em admin/__init__.py


def _get_admin_secret():
    # Busca o ADMIN_SECRET que você definiu no app.py
    # (app.config['ADMIN_SECRET'] = ADMIN_SECRET)
    return current_app.config.get("ADMIN_SECRET", "")


def _is_secret_ok(value: str) -> bool:
    sec = (value or "").strip()
    return bool(sec) and (sec == _get_admin_secret())


# ---------- rota de sanidade (já existia ou similar) ----------
@admin_bp.route("/_hello")
def hello():
    return "admin ok"


# ---------- NOVO: raiz do blueprint -> login ----------
@admin_bp.route("/", methods=["GET"])
def index():
    # /admin/ redireciona para /admin/login (mantém ?secret se vier)
    secret = (request.args.get("secret") or "").strip()
    if secret:
        return redirect(url_for(".login", secret=secret))
    return redirect(url_for(".login"))


# ---------- login ----------
@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Exibe o admin_login.html e valida a chave na submissão.
    Se ok, manda para /admin/home propagando ?secret=...
    """
    if request.method == "POST":
        # Campo normal do form
        secret_form = (request.form.get("secret") or "").strip()
        # Campo "keep_secret" que preserva o valor vindo por querystring (proxy que tira ?secret)
        keep_secret = (request.form.get("keep_secret") or "").strip()
        # Caso tenha sido passado por querystring, ainda chega aqui:
        secret_qs = (request.args.get("secret") or "").strip()

        # prioridade: o que o usuário digitou; senão o keep; senão o qs
        secret = secret_form or keep_secret or secret_qs

        if _is_secret_ok(secret):
            # ok -> painel
            return redirect(url_for(".home", secret=secret))

        flash("Chave inválida.", "error")
        # volta para GET mantendo (ou limpando) o que for preciso
        return redirect(url_for(".login"))

    # GET
    return render_template("admin_login.html")


# ---------- painel ----------
@admin_bp.route("/home", methods=["GET"])
def home():
    """
    Exige ?secret= válido, senão 403.
    Renderiza admin_home.html (os links do painel propagam ?secret=...).
    """
    secret = (request.args.get("secret") or "").strip()
    if not _is_secret_ok(secret):
        abort(403)

    return render_template("admin_home.html")
