# admin/__init__.py
from flask import Blueprint

# Deixe o Flask usar a pasta /templates da aplicação principal
admin_bp = Blueprint(
    "admin_bp",
    __name__,
    url_prefix="/admin",
)

# Importa as rotas no fim para evitar import circular
from . import views  # noqa: E402,F401
