import os, json, uuid, secrets, string, hashlib, copy
from collections import defaultdict
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from flask import Flask, render_template, request, redirect, url_for, flash, Response, abort

# ---- Auditoria (mantém como no seu projeto) ----
from audit import log_vote, verify_receipt

app = Flask(__name__)
# Segredo de sessão do Flask (defina SECRET_KEY no Render)
app.secret_key = os.environ.get("SECRET_KEY", "changeme")

# ---------------- Arquivos ----------------
CAND_FILE        = "candidates.json"   # candidatos configuráveis
VOTER_KEYS_FILE  = "voter_keys.json"   # chaves e atributos
ELECTION_FILE    = "election.json"     # guarda o prazo de encerramento (UTC)

# ---------------- Segredos (Render → Environment Variables) ----------------
ID_SALT      = os.environ.get("ID_SALT", "mude-este-salt")     # SALT para anonimato dos eleitores
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "troque-admin")  # protege rotas /admin

# Candidatos reservados (fixos no final)
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

def _squash_spaces(name: str) -> str:
    """Remove espaços nas bordas e compacta múltiplos espaços internos."""
    return " ".join((name or "").strip().split())

# ---------------- Prazo de votação (deadline) ----------------
def load_deadline():
    """Lê o prazo (UTC) do arquivo election.json. Retorna datetime aware em UTC ou None."""
    if not os.path.exists(ELECTION_FILE):
        return None
    try:
        with open(ELECTION_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        iso = data.get("deadline_utc")
        if not iso:
            return None
        return datetime.fromisoformat(iso)
    except Exception:
        return None

def save_deadline(dt_utc: datetime | None):
    """Salva o prazo (UTC) em election.json. Se None, limpa."""
    if dt_utc is None:
        clear_deadline()
        return
    data = {"deadline_utc": dt_utc.astimezone(timezone.utc).isoformat()}
    with open(ELECTION_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def clear_deadline():
    with open(ELECTION_FILE, "w", encoding="utf-8") as f:
        json.dump({"deadline_utc": None}, f, ensure_ascii=False, indent=2)

def is_voting_open() -> bool:
    """Retorna True se não houver prazo definido ou se agora (UTC) < deadline."""
    dl = load_deadline()
    if dl is None:
        return True
    now = datetime.now(timezone.utc)
    return now < dl

# ---------------- Candidatos: carregar/salvar/normalizar ----------------
def _default_candidates():
    base = ["Alice", "Bob", "Charlie"]
    return base + [RESERVED_BLANK, RESERVED_NULL]

def normalize_candidates(user_list):
    """
    - Remove vazios.
    - Compacta espaços internos e remove bordas.
    - Remove duplicados ignorando maiúsc./minúsc. (preserva a 1ª grafia vista).
    - Ignora tentativas de incluir Branco/Nulo (mesmo com variações).
    - Garante reservados no final: Branco acima de Nulo.
    """
    def is_reserved(name: str) -> bool:
        n = _squash_spaces(name).casefold()
        return n == RESERVED_BLANK.casefold() or n == RESERVED_NULL.casefold()

    seen_casefold = set()
    cleaned = []

    for c in (user_list or []):
        c = _squash_spaces(c)
        if not c:
            continue
        if is_reserved(c):
            continue
        key = c.casefold()
        if key in seen_casefold:
            continue
        seen_casefold.add(key)
        cleaned.append(c)  # preserva a grafia da 1ª ocorrência

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

# ---------------- Schulze com empates (weak orders) ----------------
def ballot_to_ranks(ballot):
    """
    Aceita formatos:
      - {"ranks": {cand: int|None}, "peso": int}  (preferido)
      - {"ranking": [cand1, cand2, ...], "peso": int}  (converte para ranks 1..N)
    Retorna (ranks_dict, peso:int).
    """
    peso = int(ballot.get("peso", 1))
    if "ranks" in ballot and isinstance(ballot["ranks"], dict):
        ranks = {}
        for k, v in ballot["ranks"].items():
            if v is None:
                ranks[k] = None
            else:
                try:
                    n = int(v)
                    ranks[k] = n if n >= 1 else None
                except:
                    ranks[k] = None
        return ranks, peso

    ranking = ballot.get("ranking", [])
    ranks = {}
    r = 1
    for cand in ranking:
        if cand not in ranks:
            ranks[cand] = r
            r += 1
    return ranks, peso

def compute_pairwise_weak(ballots, candidates):
    """
    Constrói a matriz pairwise ponderada considerando empates e não ranqueados:
      - se rank(A) < rank(B) → A > B (soma peso)
      - se rank(A) = rank(B) ou ambos None → não contribui
      - se rank(A) é int e rank(B) é None → A > B
      - se rank(A) é None e rank(B) é int → B > A
    Retorna: dict[a][b] = votos ponderados preferindo A sobre B
    """
    P = {a: {b: 0 for b in candidates if b != a} for a in candidates}
    for ballot in ballots:
        ranks, w = ballot_to_ranks(ballot)
        for i, a in enumerate(candidates):
            ra = ranks.get(a, None)
            for j, b in enumerate(candidates):
                if a == b:
                    continue
                rb = ranks.get(b, None)
                if ra is None and rb is None:
                    continue
                if rb is None and (ra is not None):
                    P[a][b] += w
                elif ra is None and (rb is not None):
                    P[b][a] += w
                else:
                    if isinstance(ra, int) and isinstance(rb, int):
                        if ra < rb:
                            P[a][b] += w
                        elif rb < ra:
                            P[b][a] += w
                        # ra == rb → empate, não contribui
    return P

def schulze_strengths(P, candidates):
    """
    Calcula as forças de caminho (Schulze) a partir de P[a][b].
    """
    S = {a: {b: 0 for b in candidates} for a in candidates}
    for a in candidates:
        for b in candidates:
            if a == b:
                continue
            if P[a][b] > P[b][a]:
                S[a][b] = P[a][b]
            else:
                S[a][b] = 0

    # Floyd–Warshall para caminho mais forte
    for i in candidates:
        for j in candidates:
            if i == j:
                continue
            for k in candidates:
                if i == k or j == k:
                    continue
                S[j][k] = max(S[j][k], min(S[j][i], S[i][k]))
    return S

def schulze_ranking_from_ballots(ballots, candidates):
    """
    Produz ranking (lista) a partir de cédulas com empates.
    Critério simples: ordenar por (vitórias, -derrotas), onde
      vitórias = |{y ≠ x : S[x][y] > S[y][x]}|
      derrotas = |{y ≠ x : S[y][x] > S[x][y]}|
    """
    P = compute_pairwise_weak(ballots, candidates)
    S = schulze_strengths(P, candidates)

    def score(x):
        wins = sum(S[x][y] > S[y][x] for y in candidates if y != x)
        losses = sum(S[y][x] > S[x][y] for y in candidates if y != x)
        return (wins, -losses)

    ranking = sorted(candidates, key=score, reverse=True)
    return ranking, P, S

# Memória dos votos desta execução (hash_da_chave -> {"ranks":{cand:rank|None}, "peso":int})
BALLOTS = {}

# ---------------- Rotas públicas ----------------
@app.route("/")
def index():
    return render_template("index.html")

def parse_numeric_form_to_ranks(form, candidates):
    """
    Constrói um dict {cand: rank|None} aceitando empates (números repetidos)
    e não ranqueados (None). Respeita voto especial (Branco/Nulo).
    """
    special = (form.get("special_vote") or "").strip().upper()
    if special in ("BLANK", "NULL"):
        pick = RESERVED_BLANK if special == "BLANK" else RESERVED_NULL
        ranks = {c: None for c in candidates}
        if pick in candidates:
            ranks[pick] = 1
        return ranks

    ranks = {c: None for c in candidates}
    idx = 0
    while True:
        c = form.get(f"cand_{idx}")
        r = form.get(f"rank_{idx}")
        if c is None and r is None:
            break
        idx += 1
        if c is None:
            continue
        c = _squash_spaces(c)
        if c not in candidates:
            continue
        if r is None or str(r).strip() == "":
            ranks[c] = None
        else:
            try:
                n = int(str(r).strip())
                ranks[c] = n if n >= 1 else None
            except:
                ranks[c] = None
    return ranks

@app.route("/vote", methods=["GET", "POST"])
def vote():
    # Bloqueia se prazo expirou (GET e POST)
    if not is_voting_open():
        return Response(
            "<h2>Votação encerrada</h2><p>O prazo para votar já expirou.</p><p><a href='/'>Voltar</a></p>",
            mimetype="text/html",
            status=403
        )

    candidates = load_candidates()

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

        # Preferimos ranks (para aceitar empates). Se vier apenas 'ranking',
        # converteremos para ranks 1..N.
        posted_ranking = request.form.getlist("ranking")
        if posted_ranking:
            # Converte para ranks estritos (1..N), os demais ficam None
            ranks = {c: None for c in candidates}
            r = 1
            for c in posted_ranking:
                if c in candidates and ranks[c] is None:
                    ranks[c] = r
                    r += 1
        else:
            # Reconstrói a partir de cand_i / rank_i permitindo duplicatas e vazios
            ranks = parse_numeric_form_to_ranks(request.form, candidates)

        # Pelo menos uma preferência (rank numérico) OU voto especial escolhido
        if not any((isinstance(v, int) and v >= 1) for v in ranks.values()):
            flash("Nenhuma preferência informada.", "error")
            return redirect(url_for("vote"))

        # Marca chave como usada e salva
        info["used"] = True
        info["used_at"] = uuid.uuid4().hex  # pode trocar por timestamp real
        peso = int(info.get("peso", 1))
        keys["keys"][voter_key] = info
        save_keys(keys)

        # Guarda voto por hash da chave (anonimato) + peso
        voter_key_h = key_hash(voter_key)
        BALLOTS[voter_key_h] = {"ranks": ranks, "peso": peso}

        # Auditoria com hash + recibo
        receipt = str(uuid.uuid4())
        # Para auditoria humana, podemos também registrar uma versão linear auxiliar:
        # ordena por rank crescente; empates ficam perto, não ranqueados vão ao fim
        linear = [c for c, v in sorted(ranks.items(), key=lambda x: (x[1] is None, x[1] or 10**9, x[0].casefold()))]
        log_vote(voter_id=voter_key_h, ranking=linear, receipt=receipt)

        return render_template("receipt.html", receipt=receipt)

    # GET
    return render_template("vote.html", candidates=candidates)

@app.route("/results")
def results():
    ballots = list(BALLOTS.values())
    if not ballots:
        return render_template("results.html", ranking=[], empty=True, total_votos=0)

    try:
        candidates = load_candidates()
        total_votos = sum(int(item.get("peso", 1)) for item in ballots)

        # Ranking oficial (Schulze com empates)
        ranking_official, pairwise, strength = schulze_ranking_from_ballots(ballots, candidates)

        debug = request.args.get("debug") == "1"
        if debug:
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

# ---------------- Painel ADMIN unificado (Candidatos + Prazo c/ detecção de fuso) ----------------
@app.route("/admin/candidates", methods=["GET", "POST"])
def admin_candidates():
    """
    Painel unificado:
    - Editar candidatos (textarea, um por linha; Branco/Nulo são fixos no fim)
    - Definir ou limpar prazo de votação (data/hora em TZ; salva em UTC)
    - Detecta automaticamente o fuso do navegador (via JS) e pré-seleciona no formulário
    """
    if not require_admin(request):
        abort(403)

    msg = None
    warn = None

    if request.method == "POST":
        action = request.form.get("action", "")
        tz_s   = (request.form.get("tz") or "America/Sao_Paulo").strip()
        if action == "save_candidates":
            raw = request.form.get("lista", "")
            lines = [_squash_spaces(ln) for ln in raw.splitlines()]
            new_list = save_candidates(lines)
            msg = "Candidatos salvos com sucesso."
            return _render_admin_candidates(new_list, msg=msg, warn=warn, tz_default=tz_s)

        elif action == "set_deadline":
            date_s = (request.form.get("date") or "").strip()
            time_s = (request.form.get("time") or "").strip()
            if not date_s or not time_s:
                warn = "Preencha data e hora para definir o prazo."
                current = load_candidates()
                return _render_admin_candidates(current, msg=msg, warn=warn, tz_default=tz_s)

            try:
                local_tz = ZoneInfo(tz_s)
                y, m, d = [int(x) for x in date_s.split("-")]
                hh, mm  = [int(x) for x in time_s.split(":")]
                local_dt = datetime(y, m, d, hh, mm, tzinfo=local_tz)
                save_deadline(local_dt.astimezone(timezone.utc))
                msg = "Prazo definido com sucesso."
            except Exception as e:
                warn = f"Erro ao definir prazo: {e}"

            current = load_candidates()
            return _render_admin_candidates(current, msg=msg, warn=warn, tz_default=tz_s)

        elif action == "clear_deadline":
            clear_deadline()
            msg = "Prazo de votação removido."
            current = load_candidates()
            return _render_admin_candidates(current, msg=msg, warn=warn)

        elif action == "set_browser_tz":
            # Vem de um post transparente do JS com o fuso detectado
            tz_s = (request.form.get("browser_tz") or "America/Sao_Paulo").strip()
            current = load_candidates()
            return _render_admin_candidates(current, msg=None, warn=None, tz_default=tz_s)

        # Ação desconhecida
        warn = "Ação inválida."
        current = load_candidates()
        return _render_admin_candidates(current, msg=msg, warn=warn)

    # GET
    current = load_candidates()
    return _render_admin_candidates(current)

def _render_admin_candidates(current, msg=None, warn=None, tz_default="America/Sao_Paulo"):
    core = [c for c in current if c not in (RESERVED_BLANK, RESERVED_NULL)]
    core_text = "\n".join(core)

    dl_utc = load_deadline()
    if dl_utc:
        try:
            local_tz = ZoneInfo(tz_default)
        except Exception:
            local_tz = ZoneInfo("America/Sao_Paulo")
        dl_local = dl_utc.astimezone(local_tz)
        deadline_html = (
            f"<p><b>Prazo atual:</b> "
            f"{dl_local.strftime('%d/%m/%Y %H:%M')} {tz_default} "
            f"(<code>{dl_utc.strftime('%Y-%m-%d %H:%M UTC')}</code>)</p>"
        )
    else:
        deadline_html = "<p><i>Nenhum prazo definido (votação aberta).</i></p>"

    status_html = ""
    if msg:  status_html += f"<p style='color:green'>{msg}</p>"
    if warn: status_html += f"<p style='color:#b45309'>{warn}</p>"

    tz_options = [
        "America/Sao_Paulo",
        "America/Bahia",
        "America/Fortaleza",
        "America/Recife",
        "America/Maceio",
        "America/Manaus",
        "America/Belem",
        "America/Boa_Vista",
        "America/Porto_Velho",
        "America/Cuiaba",
        "America/Campo_Grande",
        "America/Noronha",
        "UTC"
    ]

    html = f"""
    <!doctype html>
    <html lang="pt-BR">
      <head>
        <meta charset="utf-8">
        <title>Admin · Candidatos & Prazo</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <style>
          body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; padding: 24px; line-height:1.45; }}
          .grid {{ display:grid; gap:24px; grid-template-columns: 1fr; }}
          @media (min-width: 920px) {{ .grid {{ grid-template-columns: 1fr 1fr; }} }}
          .card {{ border:1px solid #e5e7eb; border-radius:12px; padding:16px; background:#fff; }}
          .title {{ margin:0 0 8px 0; }}
          .info {{ color:#444; background:#f6f7f9; padding:10px 12px; border-radius:6px; }}
          textarea {{ width: 100%; min-height: 240px; font: inherit; }}
          input[type="text"], input[type="date"], input[type="time"], select {{ width:100%; padding:8px; border:1px solid #d1d5db; border-radius:8px; }}
          .row {{ display:flex; gap:10px; }}
          .row > div {{ flex:1; }}
          .btn {{ background:#111827; color:#fff; border:none; padding:10px 14px; border-radius:8px; cursor:pointer; }}
          .btn:hover {{ opacity:.92; }}
          .btn-outline {{ background:#fff; color:#111827; border:1px solid #111827; }}
          .muted {{ color:#6b7280; }}
          .tag {{ display:inline-block; background:#eef2ff; color:#3730a3; padding:2px 8px; border-radius:999px; margin-left:6px; font-size:.85rem; }}
          .status {{ margin: 6px 0 12px 0; }}
        </style>
      </head>
      <body>
        <h1 class="title">Painel administrativo <span class="tag">protegido</span></h1>
        <div class="status">{status_html}</div>

        <div class="grid">

          <!-- Card CANDIDATOS -->
          <section class="card">
            <h2 class="title">Candidatos</h2>
            <div class="info">
              <p>Edite os candidatos com <b>um por linha</b>. Não inclua os especiais:
              <b>{RESERVED_BLANK}</b> e <b>{RESERVED_NULL}</b> — eles são fixos e sempre aparecem no final.</p>
            </div>

            <form method="POST">
              <input type="hidden" name="action" value="save_candidates" />
              <label for="lista"><b>Lista de candidatos</b></label><br/>
              <textarea id="lista" name="lista" placeholder="Ex.:&#10;Candidato A&#10;Candidato B&#10;Candidato C">{core_text}</textarea>
              <div style="margin-top:10px;">
                <button class="btn" type="submit">Salvar candidatos</button>
              </div>
            </form>

            <h3 style="margin-top:16px;">Ordem final aplicada:</h3>
            <ul class="muted">
              {"".join(f"<li>{c}</li>" for c in core)}
              <li><i>{RESERVED_BLANK}</i> (fixo)</li>
              <li><i>{RESERVED_NULL}</i> (fixo)</li>
            </ul>
          </section>

          <!-- Card PRAZO -->
          <section class="card">
            <h2 class="title">Prazo de votação</h2>
            {deadline_html}

            <form method="POST" id="deadlineForm" style="margin-top:8px;">
              <input type="hidden" name="action" value="set_deadline" />

              <div class="row">
                <div>
                  <label for="date"><b>Data</b></label>
                  <input id="date" name="date" type="date" />
                </div>
                <div>
                  <label for="time"><b>Hora</b></label>
                  <input id="time" name="time" type="time" />
                </div>
              </div>

              <div style="margin-top:8px;">
                <label for="tz"><b>Fuso horário</b></label>
                <select id="tz" name="tz">
                  {"".join(f'<option value="{tz}" ' + ('selected' if tz==tz_default else '') + f'>{tz}</option>' for tz in [
                      "America/Sao_Paulo","America/Bahia","America/Fortaleza","America/Recife","America/Maceio",
                      "America/Manaus","America/Belem","America/Boa_Vista","America/Porto_Velho",
                      "America/Cuiaba","America/Campo_Grande","America/Noronha","UTC"
                  ])}
                </select>
              </div>

              <div style="margin-top:10px; display:flex; gap:8px;">
                <button class="btn" type="submit">Definir prazo</button>
                <button class="btn btn-outline" type="submit" form="clearForm">Limpar prazo</button>
              </div>

              <p class="muted" style="margin-top:8px;">
                O prazo é salvo em UTC; aqui você define em um fuso local e o sistema converte automaticamente.
              </p>
            </form>

            <form method="POST" id="clearForm" style="display:none;">
              <input type="hidden" name="action" value="clear_deadline" />
            </form>

            <!-- Form invisível para informar o fuso do navegador ao servidor -->
            <form method="POST" id="tzDetectForm" style="display:none;">
              <input type="hidden" name="action" value="set_browser_tz" />
              <input type="hidden" name="browser_tz" id="browser_tz" value="">
            </form>
          </section>

        </div>

        <p style="margin-top:18px;"><a href="/">Voltar ao início</a></p>

        <script>
          // Detecta o fuso do navegador (IANA) e envia uma vez ao servidor
          (function() {{
            try {{
              var tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
              if (tz) {{
                var sel = document.getElementById("tz");
                if (sel) {{
                  for (var i=0; i<sel.options.length; i++) {{
                    if (sel.options[i].value === tz) {{
                      sel.selectedIndex = i;
                      break;
                    }}
                  }}
                }}
                var f = document.getElementById("tzDetectForm");
                if (f) {{
                  document.getElementById("browser_tz").value = tz;
                  fetch(window.location.href, {{
                    method: "POST",
                    headers: {{ "Content-Type": "application/x-www-form-urlencoded" }},
                    body: "action=set_browser_tz&browser_tz=" + encodeURIComponent(tz) + "&secret={request.args.get('secret','')}"
                  }}).catch(function(e){{ /* ignore */ }});
                }}
              }}
            }} catch(e) {{ /* ignore */ }}
          }})();
        </script>
      </body>
    </html>
    """
    return Response(html, mimetype="text/html")

# ---------------- Debug local ----------------
if __name__ == "__main__":
    # Para testes locais (em produção, configure o Start Command no Render com gunicorn)
    app.run(host="0.0.0.0", port=5000, debug=True)
