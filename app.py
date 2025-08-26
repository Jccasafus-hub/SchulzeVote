import os, hmac, hashlib, json, uuid
from flask import Flask, render_template, request, redirect, url_for, flash, Response, abort

from schulze import schulze_method
from audit import log_vote, verify_receipt

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "changeme")

# ---------- Config ----------
CANDIDATES = ["Alice", "Bob", "Charlie", "Voto em Branco", "Voto Nulo"]

ID_SALT = os.environ.get("ID_SALT", "mude-este-salt")         # troque em produção
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "troque-admin") # proteje rotas admin
VOTER_KEYS_FILE = "voter_keys.json"

# ---------- Utils ----------
def norm(s: str) -> str:
    return (s or "").strip().upper()

def key_hash(k: str) -> str:
    return hashlib.sha256((ID_SALT + norm(k)).encode()).hexdigest()

def load_keys():
    if not os.path.exists(VOTER_KEYS_FILE):
        return {"keys": {}}  # { "keys": { "CHAVE-ABC123": {"used": false, "used_at": null} } }
    with open(VOTER_KEYS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_keys(d):
    with open(VOTER_KEYS_FILE, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)

# Memória de votos (ranking por hash da chave)
BALLOTS = {}  # { key_hash: ["candA","candB",...] }

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

        keys = load_keys()
        info = keys["keys"].get(voter_key)
        if not info:
            flash("Chave inválida (não encontrada).", "error")
            return redirect(url_for("vote"))

        if info.get("used"):
            flash("Esta chave já foi utilizada.", "error")
            return redirect(url_for("index"))

        # Monta ordem final conforme inputs hidden 'ranking'
        ranking = request.form.getlist("ranking")
        if not ranking:
            flash("Nenhuma opção selecionada.", "error")
            return redirect(url_for("vote"))

        # Marca como usada e salva
        info["used"] = True
        info["used_at"] = uuid.uuid4().hex  # timestamp/nonce simples (pode ser time.time())
        keys["keys"][voter_key] = info
        save_keys(keys)

        # Guarda voto por hash (não salvamos a chave em claro)
        voter_key_h = key_hash(voter_key)
        BALLOTS[voter_key_h] = ranking

        # Auditoria com hash + recibo
        receipt = str(uuid.uuid4())
        log_vote(voter_id=voter_key_h, ranking=ranking, receipt=receipt)

        return render_template("receipt.html", receipt=receipt)

    return render_template("vote.html", candidates=CANDIDATES)

@app.route("/results")
def results():
    if not BALLOTS:
        return "Nenhum voto computado ainda."
    ranking = schulze_method(BALLOTS.values(), CANDIDATES)
    return render_template("results.html", ranking=ranking)

@app.route("/verify", methods=["GET","POST"])
def verify():
    if request.method == "POST":
        receipt = request.form.get("receipt")
        valid = verify_receipt(receipt)
        return render_template("verify.html", checked=True, valid=valid, receipt=receipt)
    return render_template("verify.html", checked=False)

# ---------- Rotas ADMIN para chaves ----------
def require_admin(req):
    token = req.args.get("secret") or req.headers.get("X-Admin-Secret")
    return (ADMIN_SECRET and token == ADMIN_SECRET)

@app.route("/admin/keys_summary")
def admin_keys_summary():
    if not require_admin(request): abort(403)
    d = load_keys()
    total = len(d["keys"])
    used = sum(1 for k, v in d["keys"].items() if v.get("used"))
    free = total - used
    body = json.dumps({"total": total, "used": used, "free": free}, ensure_ascii=False, indent=2)
    return Response(body, mimetype="application/json")

@app.route("/admin/generate_keys")
def admin_generate_keys():
    if not require_admin(request): abort(403)
    try:
        n = int(request.args.get("n", "50"))
    except:
        n = 50
    import secrets, string
    alphabet = string.ascii_uppercase + string.digits
    def mk():  # formato: ABCD-1234-XYZ9
        return "".join(secrets.choice(alphabet) for _ in range(4)) + "-" + \
               "".join(secrets.choice(alphabet) for _ in range(4)) + "-" + \
               "".join(secrets.choice(alphabet) for _ in range(4))
    d = load_keys()
    out = []
    for _ in range(n):
        key = mk()
        while key in d["keys"]:
            key = mk()
        d["keys"][key] = {"used": False, "used_at": None}
        out.append(key)

    save_keys(d)
    # retorna texto simples para copiar/colar/distribuir
    return Response("\n".join(out), mimetype="text/plain")

if __name__ == "__main__":
    app.run(debug=True)
