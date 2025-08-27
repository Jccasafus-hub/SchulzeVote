import os, json, uuid, secrets, string, hashlib, copy
from flask import Flask, render_template, request, redirect, url_for, flash, Response, abort

from schulze import schulze_method
from audit import log_vote, verify_receipt

app = Flask(__name__)
# Segredo de sessão do Flask (defina SECRET_KEY no Render)
app.secret_key = os.environ.get("SECRET_KEY", "changeme")

# ---------------- Configurações ----------------
# Inclua aqui seus candidatos (mantenha Voto em Branco e Voto Nulo)
CANDIDATES = ["Alice", "Bob", "Charlie", "Voto em Branco", "Voto Nulo"]

# Segredos e arquivos (defina no Render → Environment Variables)
ID_SALT         = os.environ.get("ID_SALT", "mude-este-salt")     # SALT para anonimato dos eleitores
ADMIN_SECRET    = os.environ.get("ADMIN_SECRET", "troque-admin")  # protege rotas /admin
VOTER_KEYS_FILE = "voter_keys.json"                               # armazena chaves e seus atributos

# ---------------- Utilidades ----------------
def norm(s: str) -> str:
    return (s or "").strip().upper()

def key_hash(k: str) -> str:
    """Hash da chave do eleitor com SALT para anonimato."""
    return hashlib.sha256((ID_SALT + norm(k)).encode()).hexdigest()

def load_keys():
    """
    Estrutura do arquivo:
    {
      "keys": {
        "ABCD-1234-XYZ9": {"used": bool, "used_at": str|None, "peso": int}
      }
    }
    """
    base = {"keys": {}}
    if not os.path.exists(VOTER_KEYS_FILE):
        return base
    with open(VOTER_KEYS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    out = {"keys": {}}
    for k, v in data.get("keys", {}).items():
        vv = copy.deepcopy(v) if isinstance(v, dict) else {}
        if "used" not in vv:
            vv["used"] = False
        if "used_at" not in vv:
            vv["used_at"] = None
        if "peso" not in vv:
            vv["peso"] = 1
        out["keys"][k] = vv
    return out

def save_keys(d):
    with open(VOTER_KEYS_FILE, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)

def require_admin(req):
    """Autoriza rota admin se ?secret=... (ou header X-Admin-Secret) bater com ADMIN_SECRET."""
    token = req.args.get("secret") or req.headers.get("X-Admin-Secret")
    return (ADMIN_SECRET and token == ADMIN_SECRET)

# Memória dos votos desta execução (hash_da_chave -> {"ranking":[...], "peso":int})
BALLOTS = {}

# ---------------- Rotas públicas ----------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/vote", methods=["GET", "POST"])
def vote():
    if request.method == "POST":
        voter_key = norm(request.form.get("voter_id", ""))
        if not voter_key:
            flash("Informe sua CHAVE de eleitor.", "error")
            return redirect(url_for("vote"))

        # Valida chave
        keys = load_keys()
        info = keys["keys"].get(voter_key)
        if not info:
            flash("Chave inválida (não encontrada).", "error")
            return redirect(url_for("vote"))

        if info.get("used"):
            flash("Esta chave já foi utilizada.", "error")
            return redirect(url_for("index"))

        # Ranking final vem como lista de 'ranking' (inputs hidden no template)
        ranking = request.form.getlist("ranking")
        if not ranking:
            flash("Nenhuma opção selecionada.", "error")
            return redirect(url_for("vote"))

        # Marca chave como usada e salva
        info["used"] = True
        info["used_at"] = uuid.uuid4().hex  # pode trocar por timestamp real, se desejar
        peso = int(info.get("peso", 1))
        keys["keys"][voter_key] = info
        save_keys(keys)

        # Guarda voto por hash da chave (anonimato) + peso
        voter_key_h = key_hash(voter_key)
        BALLOTS[voter_key_h] = {"ranking": ranking, "peso": peso}

        # Auditoria com hash + recibo
        receipt = str(uuid.uuid4())
        log_vote(voter_id=voter_key_h, ranking=ranking, receipt=receipt)

        return render_template("receipt.html", receipt=receipt)

    return render_template("vote.html", candidates=CANDIDATES)

@app.route("/results")
def results():
    if not BALLOTS:
        return "Nenhum voto computado ainda."
    # Passa votos com peso para o Schulze ponderado
    ranking = schulze_method(list(BALLOTS.values()), CANDIDATES)
    return render_template("results.html", ranking=ranking)

@app.route("/verify", methods=["GET","POST"])
def verify():
    if request.method == "POST":
        receipt = request.form.get("receipt")
        valid = verify_receipt(receipt)
        return render_template("verify.html", checked=True, valid=valid, receipt=receipt)
    return render_template("verify.html", checked=False)

# ---------------- Rotas administrativas ----------------
@app.route("/admin/keys_summary")
def admin_keys_summary():
    if not require_admin(request):
        abort(403)
    d = load_keys()
    total = len(d["keys"])
    used = sum(1 for _, v in d["keys"].items() if v.get("used"))
    free = total - used
    body = json.dumps({"total": total, "used": used, "free": free}, ensure_ascii=False, indent=2)
    return Response(body, mimetype="application/json")

@app.route("/admin/generate_keys")
def admin_generate_keys():
    if not require_admin(request):
        abort(403)
    # quantidade e peso
    try:
        n = int(request.args.get("n", "50"))
    except:
        n = 50
    try:
        peso = int(request.args.get("peso", "1"))
    except:
        peso = 1

    alphabet = string.ascii_uppercase + string.digits

    def mk():
        # Formato ABCD-1234-XYZ9
        return "".join(secrets.choice(alphabet) for _ in range(4)) + "-" + \
               "".join(secrets.choice(alphabet) for _ in range(4)) + "-" + \
               "".join(secrets.choice(alphabet) for _ in range(4))

    d = load_keys()
    out = []
    for _ in range(n):
        key = mk()
        while key in d["keys"]:
            key = mk()
        d["keys"][key] = {"used": False, "used_at": None, "peso": peso}
        out.append(key)

    save_keys(d)
    # Texto simples (uma chave por linha)
    return Response("\n".join(out), mimetype="text/plain")

@app.route("/admin/set_weight")
def admin_set_weight():
    """
    Altera o peso de uma chave existente.
    Ex.: /admin/set_weight?secret=...&key=ABCD-1234-XYZ9&peso=3
    """
    if not require_admin(request):
        abort(403)

    key = (request.args.get("key") or "").strip()
    if not key:
        return Response('{"error":"key ausente"}', status=400, mimetype="application/json")

    try:
        peso = int(request.args.get("peso", "1"))
    except:
        return Response('{"error":"peso inválido"}', status=400, mimetype="application/json")

    d = load_keys()
    if key not in d["keys"]:
        return Response('{"error":"chave não encontrada"}', status=404, mimetype="application/json")

    d["keys"][key]["peso"] = peso
    save_keys(d)
    return Response(json.dumps({"key": key, "peso": peso}, ensure_ascii=False),
                    mimetype="application/json")

@app.route("/admin/download_keys")
def download_keys():
    if not require_admin(request):
        abort(403)

    if not os.path.exists(VOTER_KEYS_FILE):
        return Response("{}", mimetype="application/json")

    with open(VOTER_KEYS_FILE, "r", encoding="utf-8") as f:
        content = f.read()

    return Response(
        content,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=voter_keys.json"}
    )

# ---------------- Debug local ----------------
if __name__ == "__main__":
    # Para testes locais (em produção use o Start Command do Render com gunicorn)
    app.run(host="0.0.0.0", port=5000, debug=True)
