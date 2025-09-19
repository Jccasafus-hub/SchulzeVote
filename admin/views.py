from flask import (
    Blueprint, render_template, request, redirect,
    url_for, session, current_app
)

# Blueprint do Admin
admin_bp = Blueprint(
    "admin_bp",
    __name__,
    url_prefix="/admin",
    template_folder="../templates",
    static_folder="../static",
)

# ======================
# Rota raiz: /admin
# ======================
@admin_bp.route("/", methods=["GET"])
def admin_index():
    secret = (request.args.get("secret") or "").strip()
    # Se tiver ?secret=, manda direto pro painel
    if secret:
        return redirect(url_for("admin_bp.home", secret=secret))
    # Senão, vai para o login
    return redirect(url_for("admin_bp.login"))

# ======================
# Login
# ======================
@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        # chave vinda do formulário
        secret = (request.form.get("secret") or "").strip()
        admin_secret = current_app.config.get("ADMIN_SECRET", "troque-admin")

        if secret == admin_secret:
            # guarda em sessão
            session["is_admin"] = True
            # redireciona para painel preservando o ?secret=
            return redirect(url_for("admin_bp.home", secret=secret))
        else:
            error = "Chave inválida."

    return render_template("admin_login.html", error=error)

# ======================
# Painel
# ======================
@admin_bp.route("/home", methods=["GET"])
def home():
    if not session.get("is_admin"):
        return redirect(url_for("admin_bp.login"))

    secret = request.args.get("secret", "")
    return render_template("admin_home.html", secret=secret)

# ======================
# Logout
# ======================
@admin_bp.route("/logout", methods=["GET"])
def logout():
    session.pop("is_admin", None)
    secret = (request.args.get("secret") or "").strip()
    # Se havia secret, mantemos na URL para facilitar re-login
    if secret:
        return redirect(url_for("admin_bp.login", secret=secret))
    return redirect(url_for("admin_bp.login"))

# ======================
# Rota de teste
# ======================
@admin_bp.route("/_hello")
def hello():
    return "admin ok"
