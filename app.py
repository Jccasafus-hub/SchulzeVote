import os, json, uuid, secrets, string, hashlib, copy
from collections import defaultdict
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from flask import Flask, render_template, request, redirect, url_for, flash, Response, abort

from audit import log_vote, verify_receipt
from schulze import schulze_method  # versão ponderada

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

# ---------------- Auditoria (pairwise e strength) ----------------
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

def build_ranking_from_numeric_form(form, candidates):
    """
    Reconstrói um ranking a partir de campos `cand_i` e `rank_i`, aceitando
    RANKING PARCIAL:
      - Itens com número válido (>=1) são ordenados por número (1,2,3,...).
      - Itens SEM número vão para o FINAL em ORDEM ALFABÉTICA.
    Regras:
      - Se vier `special_vote=BLANK` ou `NULL`, retorna ranking só com o especial.
      - Garante que reservados (Branco/Nulo) fiquem sempre no FINAL se não forem “special”.
      - Remove duplicidade de nomes e poda espaços internos.
    Retorna lista de nomes já na ordem final.
    """
    # 1) voto especial
    special = (form.get("special_vote") or "").strip().upper()
    if special in ("BLANK", "NULL"):
        pick = RESERVED_BLANK if special == "BLANK" else RESERVED_NULL
        if pick in candidates:
            return [pick]
        # Se por algum motivo não houver, segue para a lógica normal

    # 2) coleta (cand_i, rank_i)
    numbered = []
    unranked = []
    idx = 0
    seen = set()

    def clean_name(n):
        return _squash_spaces(n)

    # Percorre todos os pares até não existir o próximo índice
    while True:
        cand = form.get(f"cand_{idx}")
        rank = form.get(f"rank_{idx}")
        if cand is None and rank is None:
            break
        idx += 1
        if cand is None:
            continue
        cand = clean_name(cand)
        if not cand or cand not in candidates:
            continue
        key = cand.casefold()
        if key in seen:
            continue
        seen.add(key)

        # rank pode estar vazio (ranking parcial)
        if rank is None or str(rank).strip() == "":
            unranked.append(cand)
        else:
            try:
                n = int(str(rank).strip())
                if n >= 1:
                    numbered.append((n, cand))
                else:
                    unranked.append(cand)
            except:
                unranked.append(cand)

    # 3) ordena numerados por n crescente
    numbered.sort(key=lambda t: t[0])
    # 4) ordena não numerados por ordem alfabética (case-insensitive), mas sem tocar nos reservados agora
    def alpha_key(name: str):
        return name.casefold()
    # separa reservados dos não-reservados
    unranked_core = [c for c in unranked if c not in (RESERVED_BLANK, RESERVED_NULL)]
    unranked_resv = [c for c in unranked if c in (RESERVED_BLANK, RESERVED_NULL)]
    unranked_core.sort(key=alpha_key)

    # 5) monta lista base: numerados (na ordem) + não numerados (alfabético)
    ranking = [c for _, c in numbered] + unranked_core

    # 6) coloca reservados AO FINAL, mantendo Branco acima de Nulo se presentes
    if RESERVED_BLANK in (name for _, name in numbered) or RESERVED_BLANK in unranked_resv:
        if RESERVED_BLANK not in ranking:
            ranking.append(RESERVED_BLANK)
    if RESERVED_NULL in (name for _, name in numbered) or RESERVED_NULL in unranked_resv:
        if RESERVED_NULL not in ranking:
            ranking.append(RESERVED_NULL)

    # 7) se, por acaso, não entrou nenhum candidato (form malformado), devolve somente reservados padrão
    if not ranking:
        core = [c for c in candidates if c not in (RESERVED_BLANK, RESERVED_NULL)]
        if core:
            # Sem inputs válidos: por segurança, retorna core ordenado + reservados
            core.sort(key=alpha_key)
            ranking = core + ([RESERVED_BLANK] if RESERVED_BLANK in candidates else []) + \
                              ([RESERVED_NULL]  if RESERVED_NULL in candidates  else [])

    return ranking

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

        # 1) Tenta pegar ranking já pronto (quando o front manda 'ranking' oculto)
        ranking = request.form.getlist("ranking")

        # 2) Se não veio (ou veio vazio), reconstrói a partir de 'cand_i'/'rank_i' (aceita ranking parcial)
        if not ranking:
            ranking = build_ranking_from_numeric_form(request.form, candidates)

        # 3) Confere se pelo menos um candidato foi selecionado
        if not ranking:
            flash("Nenhuma preferência informada.", "error")
            return redirect(url_for("vote"))

        # 4) Marca chave como usada e salva
        info["used"] = True
        info["used_at"] = uuid.uuid4().hex  # pode trocar por timestamp real
        peso = int(info.get("peso", 1))
        keys["keys"][voter_key] = info
        save_keys(keys)

        # 5) Guarda voto por hash da chave (anonimato) + peso
        voter_key_h = key_hash(voter_key)
        BALLOTS[voter_key_h] = {"ranking": ranking, "peso": peso}

        # 6) Auditoria com hash + recibo
        receipt = str(uuid.uuid4())
        log_vote(voter_id=voter_key_h, ranking=ranking, receipt=receipt)

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
