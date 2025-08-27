import os, json, uuid, secrets, string, hashlib, copy
from collections import defaultdict
from flask import Flask, render_template, request, redirect, url_for, flash, Response, abort

from audit import log_vote, verify_receipt
from schulze import schulze_method  # versão ponderada instalada

app = Flask(__name__)
# Segredo de sessão do Flask (defina SECRET_KEY no Render)
app.secret_key = os.environ.get("SECRET_KEY", "changeme")

# ---------------- Configurações/Arquivos ----------------
CAND_FILE       = "candidates.json"   # <- novo: candidatos configuráveis
VOTER_KEYS_FILE = "voter_keys.json"   # chaves e atributos

# Segredos (defina no Render → Environment Variables)
ID_SALT      = os.environ.get("ID_SALT", "mude-este-salt")     # SALT para anonimato dos eleitores
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "troque-admin")  # protege rotas /admin

# Candidatos reservados (não removíveis e ordem fixa no final)
RESERVED_BLANK = "Voto em Branco"
RESERVED_NULL  = "Voto Nulo"

# ---------------- Utilidades gerais ----------------
def norm(s: str) -> str:
    return (s or "").strip().upper()

def key_hash(k: str) -> str:
    """Hash da chave do eleitor com SALT para anonimato."""
    return hashlib.sha256((ID_SALT + norm(k)).encode()).hexdigest()

def require_admin(req):
    token = req.args.get("secret") or req.headers.get("X-Admin-Secret")
    return (ADMIN_SECRET and token == ADMIN_SECRET)

# ---------------- Candidatos: carregar/salvar/normalizar ----------------
def _default_candidates():
    # Valor inicial (você pode ajustar os nomes padrão se quiser)
    base = ["Alice", "Bob", "Charlie"]
    # Reservados sempre entram ao final na ordem: Branco, depois Nulo
    return base + [RESERVED_BLANK, RESERVED_NULL]

def normalize_candidates(user_list):
    """
    - Remove vazios/duplicados
    - Garante presença dos reservados
    - Coloca os reservados no final, com Branco acima de Nulo
    """
    seen = set()
    cleaned = []
    for c in user_list:
        c = (c or "").strip()
        if not c:
            continue
        if c in (RESERVED_BLANK, RESERVED_NULL):
            # ignoramos por enquanto; serão adicionados ao final
            continue
        if c not in seen:
            seen.add(c)
            cleaned.append(c)

    # adiciona reservados no final, nessa ordem
    cleaned.append(RESERVED_BLANK)
    cleaned.append(RESERVED_NULL)
    return cleaned

def load_candidates():
    """Lê do arquivo; se não existir, cria com padrão."""
    if not os.path.exists(CAND_FILE):
        data = {"candidates": _default_candidates()}
        save_candidates(data["candidates"])
        return data["candidates"]
    with open(CAND_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    # Saneia caso alguém tenha removido reservados
    return normalize_candidates(data.get("candidates", _default_candidates()))

def save_candidates(cands_list):
    data = {"candidates": normalize_candidates(cands_list)}
    with open(CAND_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return data["candidates"]

# ---------------- Chaves: carregar/salvar ----------------
def load_keys():
    """
    Estrutura:
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

# Memória dos votos desta execução (hash_da_chave -> {"ranking":[...], "peso":int})
BALLOTS = {}

# ---------- Cálculo de auditoria (pairwise e strength) ----------
def compute_pairwise_and_strength(ballots_with_weights, candidates):
    """
    Retorna:
      pairwise: dict[a][b] = preferência ponderada por A sobre B
      strength: dict[a][b] = força do caminho mais forte de A até B (Schulze)
      ranking:  lista de candidatos ordenados (mesmo critério do schulze_method)
    """
    pairwise = {a: {b: (0 if a != b else None) for b in candidates} for a in candidates}
    for item in ballots_with_weights:
        ranking = item.get("ranking", [])
        w = int(item.get("peso", 1))
        for i, a in enumerate(ranking):
            for b in ranking[i+1:]:
                if a != b and a in candidates and b in candidates:
                    pairwise[a][b] += w

    strength = defaultdict(lambda: defaultdict(int))
    for a in candidates:
        for b in candidates:
            if a == b: 
                continue
            ab = pairwise[a][b]
            ba = pairwise[b][a]
            strength[a][b] = ab if ab > ba else 0

    for i in candidates:
        for j in candidates:
            if i == j: 
                continue
            for k in candidates:
                if k == i or k == j:
                    continue
                strength[j][k] = max(
                    strength[j][k],
                    min(strength[j][i], strength[i][k])
                )

    def score(x):
        wins = sum(strength[x][y] > strength[y][x] for y in candidates if y != x)
        losses = sum(strength[y][x] > strength[x][y] for y in candidates if y != x)
        return (wins, -losses)

    ranking = sorted(candidates, key=score, reverse=True)
    return pairwise, strength, ranking

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

        keys = load_keys()
        info = keys["keys"].get(voter_key)
        if not info:
            flash("Chave inválida (não encontrada).", "error")
            return redirect(url_for("vote"))

        if info.get("used"):
            flash("Esta chave já foi utilizada.", "error")
            return redirect(url_for("index"))

        ranking = request.form.getlist("ranking")
        if not ranking:
            flash("Nenhuma opção selecionada.", "error")
            return redirect(url_for("vote"))

        # Marca chave como usada e salva
        info["used"] = True
        info["used_at"] = uuid.uuid4().hex  # pode trocar por timestamp real
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

    # Carrega candidatos dinâmicos
    candidates = load_candidates()
    return render_template("vote.html", candidates=candidates)

@app.route("/results")
def results():
    ballots = list(BALLOTS.values())
    if not ballots:
        return render_template("results.html", ranking=[], empty=True, total_votos=0)

    try:
        candidates = load_candidates()
        total_votos = sum(int(item.get("peso", 1)) for item in ballots)

        # Ranking oficial (schulze ponderado)
        ranking_official = schulze_method(ballots, candidates)

        # Auditoria opcional
        debug = request.args.get("debug") == "1"
        if debug:
            pairwise, strength, _ = compute_pairwise_and_strength(ballots, candidates)
            return render_template(
                "results.html",
                ranking=ranking_official,
                empty=False,
                total_votos=total_votos,
                candidates=candidates,
                pairwise=pairwise,
                strength=strength
            )
        else:
            return render_template(
                "results.html",
                ranking=ranking_official,
                empty=False,
                total_votos=total_votos
            )
    except Exception as e:
        return Response(f"Erro ao calcular resultados: {e}", status=500)

@app.route("/verify", methods=["GET","POST"])
def verify():
    if request.method == "POST":
        receipt = request.form.get("receipt")
        valid = verify_receipt(receipt)
        return render_template("verify.html", checked=True, valid=valid, receipt=receipt)
    return render_template("verify.html", checked=False)

# ---------------- Rotas ADMIN: chaves ----------------
@app.route("/admin/keys_summary")
def admin_keys_summary():
    if not require_admin(request): abort(403)
    d = load_keys()
    total = len(d["keys"])
    used = sum(1 for _, v in d["keys"].items() if v.get("used"))
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
    try:
        peso = int(request.args.get("peso", "1"))
    except:
        peso = 1

    alphabet = string.ascii_uppercase + string.digits
    def mk():
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
    return Response("\n".join(out), mimetype="text/plain")

@app.route("/admin/set_weight")
def admin_set_weight():
    if not require_admin(request): abort(403)
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
    return Response(json.dumps({"key": key, "peso": peso}, ensure_ascii=False), mimetype="application/json")

@app.route("/admin/download_keys")
def download_keys():
    if not require_admin(request): abort(403)
    if not os.path.exists(VOTER_KEYS_FILE):
        return Response("{}", mimetype="application/json")
    with open(VOTER_KEYS_FILE, "r", encoding="utf-8") as f:
        content = f.read()
    return Response(
        content, mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=voter_keys.json"}
    )

# ---------------- Rotas ADMIN: candidatos ----------------
@app.route("/admin/candidates", methods=["GET", "POST"])
def admin_candidates():
    """
    Interface simples para editar candidatos:
    - GET: mostra textarea com um candidato por linha (exceto reservados)
    - POST: salva mudanças; reservados são sempre recolocados ao final
    """
    if not require_admin(request): abort(403)

    if request.method == "POST":
        raw = request.form.get("lista", "")
        lines = [ln.strip() for ln in raw.splitlines()]
        # Salva; normalize_candidates cuidará dos reservados e ordem
        new_list = save_candidates(lines)
        return _render_admin_candidates(new_list, saved=True)

    # GET
    current = load_candidates()
    return _render_admin_candidates(current, saved=False)

def _render_admin_candidates(current, saved=False):
    # quebra a lista sem mostrar os reservados na textarea (pois são fixos)
    core = [c for c in current if c not in (RESERVED_BLANK, RESERVED_NULL)]
    core_text = "\n".join(core)
    msg = "<p style='color:green;'>Salvo com sucesso.</p>" if saved else ""
    html = f"""
    <!doctype html>
    <html lang="pt-BR">
      <head>
        <meta charset="utf-8">
        <title>Admin · Candidatos</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <style>
          body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; padding: 24px; }}
          textarea {{ width: 100%; min-height: 220px; font-family: inherit; font-size: 15px; }}
          .info {{ color:#444; background:#f6f7f9; padding: 10px 12px; border-radius: 6px; }}
          .foot {{ margin-top: 14px; color:#666; }}
          .btn {{ background:#111827; color:#fff; border:none; padding:10px 14px; border-radius:8px; cursor:pointer; }}
          .btn:hover {{ opacity:.9; }}
          code {{ background:#f3f4f6; padding:2px 6px; border-radius:4px; }}
          .tag {{ display:inline-block; background:#eef2ff; color:#3730a3; padding:2px 8px; border-radius:999px; margin-left:6px; font-size:.85rem; }}
        </style>
      </head>
      <body>
        <h1>Gerenciar candidatos <span class="tag">admin</span></h1>
        {msg}
        <div class="info">
          <p>Edite os <b>candidatos</b> colocando <b>um por linha</b>. Não inclua os especiais:
          <b>{RESERVED_BLANK}</b> e <b>{RESERVED_NULL}</b> — eles serão adicionados automaticamente no final
          (Branco acima do Nulo) e não podem ser removidos.</p>
        </div>

        <form method="POST">
          <label for="lista"><b>Candidatos (um por linha)</b></label><br/>
          <textarea id="lista" name="lista" placeholder="Ex.:&#10;Candidato A&#10;Candidato B&#10;Candidato C">{core_text}</textarea>
          <div class="foot">
            <button class="btn" type="submit">Salvar</button>
          </div>
        </form>

        <h3>Como ficará a lista final:</h3>
        <ul>
          {"".join(f"<li>{c}</li>" for c in core)}
          <li><i>{RESERVED_BLANK}</i> (fixo)</li>
          <li><i>{RESERVED_NULL}</i> (fixo)</li>
        </ul>

        <p class="foot"><a href="/">Voltar ao início</a></p>
      </body>
    </html>
    """
    return Response(html, mimetype="text/html")

# ---------------- Debug local ----------------
if __name__ == "__main__":
    # Para testes locais (em produção, configure o Start Command no Render com gunicorn)
    app.run(host="0.0.0.0", port=5000, debug=True)
