from flask import Blueprint

# Todas as rotas do admin vivem aqui
admin_bp = Blueprint(
    "admin_bp",
    __name__,
    url_prefix="/admin",
    template_folder="../templates",
    static_folder="../static",
)

# Importa as rotas para registrá-las (deixe no fim para evitar import circular)
from . import views  # noqa: E402,F401
