from flask import Blueprint, render_template, request, redirect, url_for, session, flash, Response, current_app
import json
import os

# Blueprint do Admin
admin_bp = Blueprint(
    "admin_bp",
    __name__,
    url_prefix="/admin",
    template_folder="../templates",
    static_folder="../static",
)

# =================== Helpers ===================

def _require_admin(req):
    """Valida o secret na query ou no header, comparando com ADMIN_SECRET."""
    admin_secret = os.environ.get("ADMIN_SECRET", "troque-admin")
    token = req.args.get("secret") or req.headers.get("X-Admin-Secret")
    return bool(admin_secret and token == admin_secret)

def _mask(s: str) -> str:
    if not s:
        return ""
    if len(s) <= 4:
        return "***"
    return f"{s[:2]}***{s[-2:]}"

def _get_secret_from_req():
    """Pega o secret do POST (form) ou fallback do hidden keep_secret; se não houver, pega da query."""
    form_secret = (request.form.get("secret") or "").strip()
    if form_secret:
        return form_secret
    keep = (request.form.get("keep_secret") or "").strip()
    if keep:
        return keep
    return (request.args.get("secret") or "").strip()

# =================== Rotas de diagnóstico/operação ===================

@admin_bp.route("/_hello")
def _hello():
    return "admin ok"

@admin_bp.route("/_diag")
def _diag():
    """Diagnóstico rápido do ambiente/sessão/secret (sem expor o valor da chave)."""
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

# =================== Raiz do blueprint (/admin/) ===================

@admin_bp.route("/", methods=["GET"])
def root_redirect():
    """
    Abrir /admin redireciona para /admin/home se já autenticado (sessão ou secret válido),
    caso contrário manda para /admin/login. Propaga ?secret= se presente.
    """
    secret = request.args.get("secret", "")
    if session.get("admin_auth") or _require_admin(request):
        # já autenticado -> painel
        return redirect(url_for("admin_bp.home", secret=secret) + ("&no_cache=1" if secret else "?no_cache=1"))
    # não autenticado -> login
    if secret:
        return redirect(url_for("admin_bp.login", secret=secret) + "&no_cache=1")
    return redirect(url_for("admin_bp.login") + "?no_cache=1")

# =================== Login / Logout / Home ===================

@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Coleta o secret do form (ou keep_secret) e loga informações mínimas
        form_secret = _get_secret_from_req()
        current_app.logger.info(
            f"[admin_login] POST present_secret={bool(form_secret)} len={len(form_secret)}"
        )

        if not form_secret:
            flash("Informe sua chave de administrador.", "error")
            # mantém query ?secret se existir
            q = request.args.get("secret")
            return redirect(url_for("admin_bp.login", **({"secret": q} if q else {})))

        admin_secret = os.environ.get("ADMIN_SECRET", "troque-admin")
        if form_secret != admin_secret:
            flash("Chave inválida.", "error")
            q = request.args.get("secret")
            return redirect(url_for("admin_bp.login", **({"secret": q} if q else {})))

        # Autenticado
        session["admin_auth"] = True

        # Redireciona para o painel, propagando o secret e adicionando no_cache=1 para evitar cache
        return redirect(url_for("admin_bp.home", secret=form_secret) + "&no_cache=1")

    # GET -> mostra o formulário
    return render_template("admin_login.html")

@admin_bp.route("/home")
def home():
    """
    Painel do Administrador.
    - Se a sessão tiver admin_auth True, entra.
    - Caso contrário, aceita acesso direto via ?secret válido (útil em Safari/iOS com cookies restritos).
    """
    secret = request.args.get("secret", "")
    if not session.get("admin_auth"):
        if not _require_admin(request):
            # não autenticado -> login (propaga secret se houver)
            if secret:
                return redirect(url_for("admin_bp.login", secret=secret) + "&no_cache=1")
            return redirect(url_for("admin_bp.login") + "?no_cache=1")

    # Renderiza o painel; os templates propagam ?secret nos links quando presente.
    return render_template("admin_home.html", secret=secret)

@admin_bp.route("/logout")
def logout():
    """
    Sai do painel. Mantém ?secret na URL do login para facilitar retorno, se desejar.
    """
    secret = request.args.get("secret", "")
    session.pop("admin_auth", None)
    flash("Você saiu do painel do administrador.", "info")
    if secret:
        return redirect(url_for("admin_bp.login", secret=secret) + "&no_cache=1")
    return redirect(url_for("admin_bp.login") + "?no_cache=1")
