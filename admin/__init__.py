from flask import Blueprint

# Blueprint do Admin
# - url_prefix: todas as rotas começam com /admin
# - template_folder/static_folder: apontam para as pastas do app principal
admin_bp = Blueprint(
    "admin_bp",
    __name__,
    url_prefix="/admin",
    template_folder="../templates",
    static_folder="../static",
)

# Importa as rotas para registrá-las no blueprint
# (deixar no final para evitar import circular)
from . import views  # noqa: E402,F401
