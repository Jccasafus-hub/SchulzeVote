from flask import Blueprint

# cria o blueprint do admin com prefixo /admin
admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

# importa as rotas definidas em views.py
from . import views
