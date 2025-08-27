import os, json, uuid, secrets, string, hashlib, copy
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, Response, abort, session
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "mude-isto")

# --------- Arquivos / diretórios ----------
CAND_FILE        = "candidates.json"   # candidatos
VOTER_KEYS_FILE  = "voter_keys.json"   # chaves
ELECTION_FILE    = "election.json"     # election_id, deadline_utc, meta por votação
REGISTRY_FILE    = "user_registry.json" # usuarios (ex-RA): key atribuída, senha (hash), peso, used, attempts

DATA_DIR   = Path("data")
BAL_DIR    = DATA_DIR / "ballots"
AUDIT_DIR  = DATA_DIR / "audit"
BAL_DIR.mkdir(parents=True, exist_ok=True)
AUDIT_DIR.mkdir(parents=True, exist_ok=True)

# --------- Segredos / Env ----------
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "troque-admin")
ID_SALT      = os.environ.get("ID_SALT", "mude-este-salt")

# --------- Candidatos especiais ----------
RESERVED_BLANK = "Voto em Branco"
RESERVED_NULL  = "Voto Nulo"

# --------- Utilidades ----------
def norm(s: str) -> str:
    return (s or "").strip().upper()

def _squash_spaces(s: str) -> str:
    return " ".join((s or "").strip().split())

def key_hash(k: str) -> str:
    return hashlib.sha256((ID_SALT + norm(k)).encode()).hexdigest()

def require_admin(req):
    token = req.args.get("secret") or req.headers.get("X-Admin-Secret")
    return (ADMIN_SECRET and token == ADMIN_SECRET)

# --------- Persistência geral ----------
def _read_json(path, default):
    if not os.path.exists(path): return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return default

def _write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# --------- Election (id, deadline, meta) ----------
def load_election_doc():
    d = _read_json(ELECTION_FILE, {})
    d.setdefault("election_id", "default")
    d.setdefault("deadline_utc", None)
    d.setdefault("meta", {})  # {eid: {title, date, time, tz, updated_at}}
    return d

def save_election_doc(d):
    _write_json(ELECTION_FILE, d)

def get_current_election_id():
    return load_election_doc().get("election_id", "default")

def set_current_election_id(eid: str):
    d = load_election_doc()
    d["election_id"] = eid
    save_election_doc(d)

def set_election_meta(eid: str, title: str, date_s: str, time_s: str, tz_s: str):
    d = load_election_doc()
    d["meta"][eid] = {
        "title": (title or "").strip(),
        "date": (date_s or "").strip(),
        "time": (time_s or "").strip(),
        "tz":   (tz_s or "America/Sao_Paulo").strip(),
        "updated_at": datetime.utcnow().isoformat() + "Z"
    }
    save_election_doc(d)

def get_election_meta(eid: str):
    return load_election_doc().get("meta", {}).get(eid, None)

def load_deadline():
    iso = load_election_doc().get("deadline_utc")
    if not iso: return None
    try: return datetime.fromisoformat(iso)
    except: return None

def save_deadline(dt_utc):
    d = load_election_doc()
    d["deadline_utc"] = None if dt_utc is None else dt_utc.astimezone(timezone.utc).isoformat()
    save_election_doc(d)

def is_voting_open():
    dl = load_deadline()
    if dl is None: return True
    return datetime.now(timezone.utc) < dl

# --------- Arquivos de domínio ----------
def _default_candidates():
    return ["Alice","Bob","Charlie", RESERVED_BLANK, RESERVED_NULL]

def normalize_candidates(user_list):
    def is_reserved(name: str) -> bool:
        n = _squash_spaces(name).casefold()
        return n in (RESERVED_BLANK.casefold(), RESERVED_NULL.casefold())
    seen = set()
    cleaned = []
    for c in (user_list or []):
        c = _squash_spaces(c)
        if not c: continue
        if is_reserved(c): continue
        k = c.casefold()
        if k in seen: continue
        seen.add(k); cleaned.append(c)
    cleaned.append(RESERVED_BLANK)
    cleaned.append(RESERVED_NULL)
    return cleaned

def load_candidates():
    d = _read_json(CAND_FILE, {})
    if not d:
        save_candidates(_default_candidates())
        return _default_candidates()
    return normalize_candidates(d.get("candidates", _default_candidates()))

def save_candidates(lst):
    _write_json(CAND_FILE, {"candidates": normalize_candidates(lst)})
    return load_candidates()

def load_keys():
    d = _read_json(VOTER_KEYS_FILE, {"keys": {}})
    # normaliza campos
    for k, v in list(d.get("keys", {}).items()):
        v.setdefault("used", False)
        v.setdefault("used_at", None)
        v.setdefault("peso", 1)
    return d

def save_keys(d):
    _write_json(VOTER_KEYS_FILE, d)

def load_registry():
    d = _read_json(REGISTRY_FILE, {"users": {}})
    # estrutura: users: { user_id: {key, used, pwd_hash, peso, attempts} }
    for u, v in list(d.get("users", {}).items()):
        v.setdefault("used", False)
        v.setdefault("peso", 1)
        v.setdefault("attempts", {}) # por election_id: contador
    return d

def save_registry(d):
    _write_json(REGISTRY_FILE, d)

# --------- Auditoria ----------
def ballots_path(eid: str) -> Path:
    return BAL_DIR / f"{eid}.json"

def audit_path(eid: str) -> Path:
    return AUDIT_DIR / f"{eid}.log"

def load_ballots(eid: str):
    return _read_json(str(ballots_path(eid)), [])

def save_ballots(eid: str, items):
    _write_json(str(ballots_path(eid)), items)

def append_ballot(eid: str, ballot_obj: dict):
    items = load_ballots(eid)
    items.append(ballot_obj)
    save_ballots(eid, items)

def audit_line(eid: str, text: str):
    p = audit_path(eid)
    with open(p, "a", encoding="utf-8") as f:
        f.write(text.rstrip() + "\n")

# --------- Schulze (empates/cedulas parciais) ----------
def ballot_to_ranks(ballot):
    peso = int(ballot.get("peso", 1))
    if "ranks" in ballot and isinstance(ballot["ranks"], dict):
        ranks = {}
        for k, v in ballot["ranks"].items():
            if v is None: ranks[k] = None
            else:
                try:
                    n = int(v)
                    ranks[k] = n if n >= 1 else None
                except:
                    ranks[k] = None
        return ranks, peso
    ranking = ballot.get("ranking", [])
    r = 1; ranks = {}
    for c in ranking:
        if c not in ranks:
            ranks[c] = r; r += 1
    return ranks, peso

def compute_pairwise_weak(ballots, candidates):
    P = {a:{b:0 for b in candidates if b!=a} for a in candidates}
    for ballot in ballots:
        ranks, w = ballot_to_ranks(ballot)
        for a in candidates:
            ra = ranks.get(a, None)
            for b in candidates:
                if a==b: continue
                rb = ranks.get(b, None)
                if ra is None and rb is None: continue
                if rb is None and (ra is not None): P[a][b] += w
                elif ra is None and (rb is not None): P[b][a] += w
                else:
                    if isinstance(ra,int) and isinstance(rb,int):
                        if ra < rb: P[a][b] += w
                        elif rb < ra: P[b][a] += w
    return P

def schulze_strengths(P, candidates):
    S = {a:{b:0 for b in candidates} for a in candidates}
    for a in candidates:
        for b in candidates:
            if a==b: continue
            S[a][b] = P[a][b] if P[a][b] > P[b][a] else 0
    for i in candidates:
        for j in candidates:
            if i==j: continue
            for k in candidates:
                if i==k or j==k: continue
                S[j][k] = max(S[j][k], min(S[j][i], S[i][k]))
    return S

def schulze_ranking_from_ballots(ballots, candidates):
    P = compute_pairwise_weak(ballots, candidates)
    S = schulze_strengths(P, candidates)
    def score(x):
        wins   = sum(S[x][y] > S[y][x] for y in candidates if y!=x)
        losses = sum(S[y][x] > S[x][y] for y in candidates if y!=x)
        return (wins, -losses)
    ranking = sorted(candidates, key=score, reverse=True)
    return ranking, P, S

# --------- Helpers chaves ----------
def _mk_key():
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(4)) + "-" + \
           "".join(secrets.choice(alphabet) for _ in range(4)) + "-" + \
           "".join(secrets.choice(alphabet) for _ in range(4))

def _assigned_keys_set():
    reg = load_registry()
    out = set()
    for uid, entry in reg.get("users", {}).items():
        k = (entry or {}).get("key")
        if k: out.add(k)
    return out

def _free_keys_from_pool():
    keys = load_keys()["keys"]
    assigned = _assigned_keys_set()
    return [k for k, info in keys.items() if not info.get("used") and k not in assigned]

# ===================== ROTAS PÚBLICAS =====================

@app.route("/")
def index():
    # Botões para votar, ver resultados e auditoria
    return render_template("index.html", get_current_election_id=get_current_election_id)

@app.route("/register", methods=["GET","POST"])
def register():
    # Cadastro: usuario + senha (admin nunca vê)
    if request.method == "POST":
        user_id = (request.form.get("user_id") or "").strip()
        pw = (request.form.get("password") or "").strip()
        pw2= (request.form.get("password2") or "").strip()
        if not user_id or not pw or not pw2:
            flash("Preencha usuário e senha (2x).", "error"); return redirect(url_for("register"))
        if pw != pw2:
            flash("As senhas não conferem.", "error"); return redirect(url_for("register"))
        reg = load_registry()
        users = reg.get("users", {})
        entry = users.get(user_id, {"used": False, "peso": 1, "attempts": {}})
        entry["pwd_hash"] = generate_password_hash(pw)
        users[user_id] = entry
        reg["users"] = users
        save_registry(reg)
        session["user_id"] = user_id
        flash("Cadastro realizado. Você está conectado.", "success")
        return redirect(url_for("vote"))
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        user_id = (request.form.get("user_id") or "").strip()
        pw = (request.form.get("password") or "").strip()
        reg = load_registry()
        entry = reg.get("users", {}).get(user_id)
        if not entry or not entry.get("pwd_hash") or not check_password_hash(entry["pwd_hash"], pw):
            flash("Usuário ou senha inválidos.", "error"); return redirect(url_for("login"))
        session["user_id"] = user_id
        flash("Login realizado.", "success")
        return redirect(url_for("vote"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("Você saiu.", "info")
    return redirect(url_for("index"))

def parse_numeric_form_to_ranks(form, candidates):
    special = (form.get("special_vote") or "").strip().upper()
    if special in ("BLANK","NULL"):
        pick = RESERVED_BLANK if special=="BLANK" else RESERVED_NULL
        ranks = {c: None for c in candidates}
        if pick in candidates: ranks[pick] = 1
        return ranks
    ranks = {c: None for c in candidates}
    idx = 0
    while True:
        c = form.get(f"cand_{idx}")
        r = form.get(f"rank_{idx}")
        if c is None and r is None: break
        idx += 1
        if c is None: continue
        c = _squash_spaces(c)
        if c not in candidates: continue
        if not r or str(r).strip()=="":
            ranks[c] = None
        else:
            try:
                n = int(str(r).strip())
                ranks[c] = n if n>=1 else None
            except:
                ranks[c] = None
    return ranks

def _inc_attempt(user_id, eid):
    reg = load_registry()
    entry = reg.get("users", {}).get(user_id, {"attempts": {}})
    attempts = entry.get("attempts", {})
    attempts[eid] = int(attempts.get(eid, 0)) + 1
    entry["attempts"] = attempts
    reg["users"][user_id] = entry
    save_registry(reg)
    return attempts[eid]

@app.route("/vote", methods=["GET","POST"])
def vote():
    # bloqueio por prazo
    if not is_voting_open():
        return Response("<h2>Votação encerrada</h2><p>O prazo expirou.</p><p><a href='/'>Início</a></p>", mimetype="text/html", status=403)

    candidates = load_candidates()
    if request.method == "POST":
        # exige login
        user_id = session.get("user_id")
        if not user_id:
            flash("Faça login para votar.", "error"); return redirect(url_for("login"))

        # valida chave (senha de votação) e correspondência com user_id
        voter_key = norm(request.form.get("voter_id", ""))
        if not voter_key:
            flash("Informe sua CHAVE de votação.", "error"); return redirect(url_for("vote"))

        reg = load_registry()
        entry = reg.get("users", {}).get(user_id)
        if not entry:
            flash("Usuário não habilitado.", "error"); return redirect(url_for("login"))

        expected_key = (entry or {}).get("key")
        if not expected_key:
            flash("Seu usuário ainda não tem uma chave atribuída.", "error"); return redirect(url_for("index"))

        eid = get_current_election_id()
        # limite de 5 tentativas por eleição
        current_attempts = int(entry.get("attempts", {}).get(eid, 0))
        if current_attempts >= 5:
            flash("Limite de tentativas de chave atingido para esta votação.", "error")
            audit_line(eid, f"ATTEMPT-LIMIT {datetime.utcnow().isoformat()}Z user={user_id} ip={request.remote_addr or '-'}")
            return redirect(url_for("index"))

        if voter_key != expected_key:
            n = _inc_attempt(user_id, eid)
            flash("Chave inválida para este usuário.", "error")
            audit_line(eid, f"ATTEMPT {datetime.utcnow().isoformat()}Z user={user_id} provided={voter_key} ip={request.remote_addr or '-'} count={n}")
            return redirect(url_for("vote"))

        # confere status da chave
        keys_doc = load_keys()
        kinfo = keys_doc["keys"].get(voter_key)
        if not kinfo:
            flash("Chave inexistente.", "error"); return redirect(url_for("vote"))
        if kinfo.get("used"):
            flash("Esta chave já foi usada.", "error"); return redirect(url_for("index"))

        # montar ranks (empates permitidos)
        posted_ranking = request.form.getlist("ranking")
        if posted_ranking:
            ranks = {c: None for c in candidates}
            r=1
            for c in posted_ranking:
                if c in candidates and ranks[c] is None:
                    ranks[c] = r; r += 1
        else:
            ranks = parse_numeric_form_to_ranks(request.form, candidates)

        if not any((isinstance(v,int) and v>=1) for v in ranks.values()):
            flash("Nenhuma preferência informada.", "error"); return redirect(url_for("vote"))

        # peso: prioriza peso no registro do usuário; senão, peso da chave; default 1
        peso = int(entry.get("peso", kinfo.get("peso", 1)))

        # marca chave usada
        kinfo["used"] = True
        kinfo["used_at"] = datetime.utcnow().isoformat() + "Z"
        keys_doc["keys"][voter_key] = kinfo
        save_keys(keys_doc)

        # marca usuário como usado (para esta votação)
        entry["used"] = True
        # zera attempts desta votação
        atts = entry.get("attempts", {})
        atts[eid] = 0
        entry["attempts"] = atts
        reg["users"][user_id] = entry
        save_registry(reg)

        # salva voto (apenas hash da chave) + peso
        voter_key_h = key_hash(voter_key)
        append_ballot(eid, {"ranks": ranks, "peso": peso, "voter": voter_key_h})

        # auditoria
        receipt = str(uuid.uuid4())
        audit_line(eid, f"VOTE {datetime.utcnow().isoformat()}Z voter={voter_key_h} receipt={receipt} ip={request.remote_addr or '-'}")

        return render_template("receipt.html", receipt=receipt)

    # GET
    return render_template("vote.html", candidates=candidates)

# --------- Resultados / públicos ----------
@app.route("/results")
def results_current():
    # redireciona para a votação atual
    return redirect(url_for("public_results", eid=get_current_election_id()))

@app.route("/public/elections")
def public_elections():
    eids = sorted([p.stem for p in BAL_DIR.glob("*.json")])
    return Response(json.dumps({"elections": eids}, ensure_ascii=False, indent=2), mimetype="application/json")

@app.route("/public/<eid>/results")
def public_results(eid):
    ballots = load_ballots(eid)
    if not ballots:
        meta = get_election_meta(eid)
        return render_template("results.html", ranking=[], empty=True, total_votos=0, election_id=eid, election_meta=meta)
    try:
        candidates = load_candidates()
        ranking, pairwise, strength = schulze_ranking_from_ballots(ballots, candidates)
        meta = get_election_meta(eid)
        return render_template(
            "results.html",
            ranking=ranking, empty=False,
            total_votos=sum(int(b.get("peso",1)) for b in ballots),
            election_id=eid, election_meta=meta,
            candidates=candidates if request.args.get("debug")=="1" else None,
            pairwise=pairwise if request.args.get("debug")=="1" else None,
            strength=strength if request.args.get("debug")=="1" else None
        )
    except Exception as e:
        return Response(f"Erro ao calcular resultados: {e}", status=500)

@app.route("/public/<eid>/audit")
def public_audit(eid):
    p = audit_path(eid)
    meta = get_election_meta(eid)
    head = ""
    if meta:
        head = (f"<h1>{meta.get('title','Auditoria')}</h1>"
                f"<p><b>ID:</b> {eid}"
                + (f" • <b>Data/Hora:</b> {meta.get('date','')} {meta.get('time','')} {meta.get('tz','')}" if meta.get('date') and meta.get('time') else "")
                + "</p>")
    else:
        head = f"<h1>Auditoria</h1><p><b>ID:</b> {eid}</p>"
    if not p.exists():
        return Response(head + "<pre>(Sem auditoria para esta votação.)</pre>", mimetype="text/html")
    with open(p, "r", encoding="utf-8") as f:
        lines = f.readlines()
    return Response(head + "<pre>" + "".join(lines) + "</pre>", mimetype="text/html")

# ===================== ROTAS ADMIN =====================

@app.route("/admin/candidates", methods=["GET","POST"])
def admin_candidates():
    if not require_admin(request): abort(403)
    msg = warn = None
    if request.method == "POST":
        action = request.form.get("action","")
        if action == "save_candidates":
            raw = request.form.get("lista","")
            lines = [_squash_spaces(ln) for ln in raw.splitlines()]
            save_candidates(lines)
            msg = "Candidatos salvos."
        elif action == "set_deadline":
            date_s = (request.form.get("date") or "").strip()
            time_s = (request.form.get("time") or "").strip()
            tz_s   = (request.form.get("tz") or "America/Sao_Paulo").strip()
            if not date_s or not time_s:
                warn = "Informe data e hora."
            else:
                try:
                    local_tz = ZoneInfo(tz_s)
                    y,m,d = [int(x) for x in date_s.split("-")]
                    hh,mm = [int(x) for x in time_s.split(":")]
                    local_dt = datetime(y,m,d,hh,mm,tzinfo=local_tz)
                    save_deadline(local_dt.astimezone(timezone.utc))
                    msg = "Prazo definido."
                except Exception as e:
                    warn = f"Erro: {e}"
        elif action == "clear_deadline":
            save_deadline(None); msg="Prazo removido."
    current = load_candidates()
    core = [c for c in current if c not in (RESERVED_BLANK, RESERVED_NULL)]
    dl_utc = load_deadline()
    tz_default = "America/Sao_Paulo"
    if dl_utc:
        local = dl_utc.astimezone(ZoneInfo(tz_default))
        deadline_html = f"<p><b>Prazo atual:</b> {local.strftime('%d/%m/%Y %H:%M')} {tz_default}</p>"
    else:
        deadline_html = "<p><i>Nenhum prazo definido.</i></p>"

    # Pequena UI (HTML inline) — simples:
    html = f"""
    <!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><title>Admin · Candidatos & Prazo</title>
    <style>body{{font-family:system-ui;padding:24px}} textarea{{width:100%;min-height:200px}}</style></head><body>
      <h1>Admin · Candidatos & Prazo</h1>
      {"<p style='color:green'>"+msg+"</p>" if msg else ""}
      {"<p style='color:#b45309'>"+warn+"</p>" if warn else ""}
      <form method="POST">
        <input type="hidden" name="action" value="save_candidates">
        <p><b>Candidatos</b> (um por linha; <i>{RESERVED_BLANK}</i>/<i>{RESERVED_NULL}</i> são fixos no fim):</p>
        <textarea name="lista">{chr(10).join(core)}</textarea><br><br>
        <button>Salvar candidatos</button>
      </form>
      <hr>
      <h2>Prazo de votação</h2>
      {deadline_html}
      <form method="POST">
        <input type="hidden" name="action" value="set_deadline">
        <label>Data: <input type="date" name="date"></label>
        <label>Hora: <input type="time" name="time"></label>
        <label>Fuso: 
          <select name="tz">
            {"".join(f"<option>{tz}</option>" for tz in ["America/Sao_Paulo","America/Bahia","America/Fortaleza","America/Recife","America/Maceio","America/Manaus","America/Belem","America/Boa_Vista","America/Porto_Velho","America/Cuiaba","America/Campo_Grande","America/Noronha","UTC"])}
          </select>
        </label>
        <button>Definir prazo</button>
      </form>
      <form method="POST" style="margin-top:8px">
        <input type="hidden" name="action" value="clear_deadline"><button>Limpar prazo</button>
      </form>
      <p style="margin-top:16px"><a href="/admin/election_meta?secret={request.args.get('secret','')}">Metadados da votação</a></p>
      <p><a href="/">Início</a></p>
    </body></html>
    """
    return Response(html, mimetype="text/html")

# Metadados (título, data, hora, tz) — exigidos para exibir claros nos relatórios
@app.route("/admin/election_meta", methods=["GET","POST"])
def admin_election_meta():
    if not require_admin(request): abort(403)
    d = load_election_doc()
    msg = warn = None
    if request.method == "POST":
        eid   = (request.form.get("eid") or d.get("election_id","default")).strip()
        title = (request.form.get("title") or "").strip()
        date  = (request.form.get("date") or "").strip()
        time  = (request.form.get("time") or "").strip()
        tz    = (request.form.get("tz") or "America/Sao_Paulo").strip()
        if not eid or not title or not date or not time:
            warn = "Preencha EID, título, data e hora."
        else:
            set_election_meta(eid, title, date, time, tz)
            d["election_id"] = eid
            save_election_doc(d)
            msg = "Metadados salvos."
    meta = get_election_meta(d.get("election_id"))
    sel_tz = (meta or {}).get("tz", "America/Sao_Paulo")
    tz_opts = ["America/Sao_Paulo","America/Bahia","America/Fortaleza","America/Recife","America/Maceio",
               "America/Manaus","America/Belem","America/Boa_Vista","America/Porto_Velho",
               "America/Cuiaba","America/Campo_Grande","America/Noronha","UTC"]
    html = f"""
    <!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><title>Admin · Metadados</title>
    <style>body{{font-family:system-ui;padding:24px}} input,select{{padding:8px;border:1px solid #ccc;border-radius:8px}}</style></head><body>
      <h1>Metadados da votação</h1>
      {"<p style='color:green'>"+msg+"</p>" if msg else ""}
      {"<p style='color:#b45309'>"+warn+"</p>" if warn else ""}
      <form method="POST">
        <p><label>EID <input name="eid" value="{d.get('election_id','default')}" required></label></p>
        <p><label>Título <input name="title" value="{(meta or {}).get('title','')}" required placeholder="Ex.: Eleição da Turma 2025"></label></p>
        <p>
          <label>Data <input type="date" name="date" value="{(meta or {}).get('date','')}" required></label>
          <label>Hora <input type="time" name="time" value="{(meta or {}).get('time','')}" required></label>
          <label>Fuso <select name="tz">{"".join(f'<option value="{tz}" '+('selected' if tz==sel_tz else '')+f'>{tz}</option>' for tz in tz_opts)}</select></label>
        </p>
        <button>Salvar</button>
      </form>
      <p style="margin-top:12px"><a href="/admin/assign_ui?secret={request.args.get('secret','')}">Atribuir chaves (UI)</a></p>
      <p><a href="/">Início</a></p>
    </body></html>
    """
    return Response(html, mimetype="text/html")

# ---- Admin API: gerar/atribuir em lote ----
@app.route("/admin/assign_batch_generate", methods=["GET","POST"])
def admin_assign_batch_generate():
    if not require_admin(request): abort(403)
    ras_param = (request.values.get("ras") or "").strip()
    if not ras_param: return Response('{"error":"informe ras=U1,U2,..."}', status=400, mimetype="application/json")
    try: peso = int(request.values.get("peso","1"))
    except: return Response('{"error":"peso inválido"}', status=400, mimetype="application/json")
    users = [r.strip() for r in ras_param.split(",") if r.strip()]
    users = list(dict.fromkeys(users))
    keys_doc = load_keys()
    reg = load_registry()
    assigned = {}
    for uid in users:
        ent = reg["users"].get(uid, {"used": False, "peso": 1, "attempts": {}})
        if ent.get("key"):
            assigned[uid] = ent["key"]
            reg["users"][uid] = ent
            continue
        # gera nova chave
        k = _mk_key()
        while k in keys_doc["keys"]:
            k = _mk_key()
        keys_doc["keys"][k] = {"used": False, "used_at": None, "peso": peso}
        ent["key"] = k
        reg["users"][uid] = ent
        assigned[uid] = k
    save_keys(keys_doc); save_registry(reg)
    return Response(json.dumps({"ok": True, "assigned": assigned}, ensure_ascii=False, indent=2), mimetype="application/json")

@app.route("/admin/assign_batch_use_pool", methods=["GET","POST"])
def admin_assign_batch_use_pool():
    if not require_admin(request): abort(403)
    ras_param = (request.values.get("ras") or "").strip()
    if not ras_param: return Response('{"error":"informe ras=U1,U2,..."}', status=400, mimetype="application/json")
    users = [r.strip() for r in ras_param.split(",") if r.strip()]
    users = list(dict.fromkeys(users))
    keys_doc = load_keys()
    reg = load_registry()
    pool = _free_keys_from_pool()
    need = len([u for u in users if not reg["users"].get(u, {}).get("key")])
    if need > len(pool):
        return Response(json.dumps({"error":"chaves livres insuficientes","livres":len(pool)} ,ensure_ascii=False), status=409, mimetype="application/json")
    assigned = {}
    i = 0
    for uid in users:
        ent = reg["users"].get(uid, {"used": False, "peso": 1, "attempts": {}})
        if ent.get("key"):
            assigned[uid] = ent["key"]
            reg["users"][uid] = ent
            continue
        k = pool[i]; i += 1
        if k not in keys_doc["keys"] or keys_doc["keys"][k].get("used"):
            return Response('{"error":"inconsistência no pool"}', status=500, mimetype="application/json")
        ent["key"] = k
        reg["users"][uid] = ent
        assigned[uid] = k
    save_registry(reg)
    return Response(json.dumps({"ok": True, "assigned": assigned}, ensure_ascii=False, indent=2), mimetype="application/json")

# ---- Admin API: alterar peso do usuário manualmente ----
@app.route("/admin/set_user_weight")
def admin_set_user_weight():
    if not require_admin(request): abort(403)
    uid = (request.args.get("user") or "").strip()
    if not uid: return Response('{"error":"user ausente"}', status=400, mimetype="application/json")
    try: peso = int(request.args.get("peso","1"))
    except: return Response('{"error":"peso inválido"}', status=400, mimetype="application/json")
    reg = load_registry()
    ent = reg["users"].get(uid)
    if not ent: return Response('{"error":"user não encontrado"}', status=404, mimetype="application/json")
    ent["peso"] = peso
    reg["users"][uid] = ent
    save_registry(reg)
    return Response(json.dumps({"ok": True, "user": uid, "peso": peso}, ensure_ascii=False), mimetype="application/json")

# ---- Admin API: listas para UI (tabelas ao vivo) ----
@app.route("/admin/keys_list")
def admin_keys_list():
    if not require_admin(request): abort(403)
    return Response(json.dumps(load_keys(), ensure_ascii=False, indent=2), mimetype="application/json")

@app.route("/admin/pool_list")
def admin_pool_list():
    if not require_admin(request): abort(403)
    return Response(json.dumps({"pool": _free_keys_from_pool()}, ensure_ascii=False, indent=2), mimetype="application/json")

@app.route("/admin/users_list")
def admin_users_list():
    if not require_admin(request): abort(403)
    return Response(json.dumps(load_registry(), ensure_ascii=False, indent=2), mimetype="application/json")

# ---- Página admin: Assign UI ----
@app.route("/admin/assign_ui")
def admin_assign_ui():
    if not require_admin(request): abort(403)
    secret = request.args.get("secret","")
    html = f"""
    <!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><title>Admin · Atribuir chaves</title>
    <style>
      body{{font-family:system-ui;padding:24px}} textarea{{width:100%;min-height:120px}}
      .grid{{display:grid;gap:16px}} .col{{border:1px solid #e5e7eb;padding:12px;border-radius:10px}}
      table{{border-collapse:collapse;width:100%}} th,td{{border:1px solid #e5e7eb;padding:6px;text-align:left;font-size:.95rem}}
      .row{{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0}} input[type=number]{{width:120px}}
      .btn{{padding:8px 12px;border-radius:8px;border:1px solid #111827;background:#111827;color:#fff;cursor:pointer}}
      .btn2{{padding:8px 12px;border-radius:8px;border:1px solid #111827;background:#fff;cursor:pointer}}
      pre{{background:#f9fafb;padding:10px;border-radius:8px;max-height:240px;overflow:auto}}
    </style></head><body>
      <h1>Atribuir chaves (lote)</h1>
      <div class="col">
        <p>Cole <b>usuários</b> (um por linha). Ex.:<br><code>u20230001</code><br><code>u20230002</code></p>
        <textarea id="usersBox" placeholder="u1&#10;u2&#10;u3"></textarea>
        <div class="row">
          <label>Peso padrão: <input type="number" id="peso" value="1" min="1"></label>
          <button class="btn" onclick="genAssign()">Gerar e atribuir</button>
          <button class="btn2" onclick="poolAssign()">Atribuir do pool</button>
        </div>
        <div><b>Resultado:</b><pre id="resultBox">(aguardando)</pre></div>
      </div>

      <h2 style="margin-top:16px">Visão geral</h2>
      <div class="grid" style="grid-template-columns:1fr 1fr">
        <div class="col">
          <h3>Chaves (voter_keys.json)</h3>
          <div id="keysTable">carregando...</div>
        </div>
        <div class="col">
          <h3>Pool (livres e não atribuídas)</h3>
          <div id="poolTable">carregando...</div>
        </div>
      </div>
      <div class="col" style="margin-top:16px">
        <h3>Usuários (user_registry.json)</h3>
        <div id="usersTable">carregando...</div>
      </div>

      <script>
        const secret = {json.dumps(secret)};
        function linesToCSV(list){{ return list.map(x=>x.join(',')).join('\\n'); }}
        function parseUsers(){{
          const t = document.getElementById('usersBox').value.trim();
          return t ? t.split(/\\r?\\n/).map(s=>s.trim()).filter(Boolean) : [];
        }}
        async function genAssign(){{
          const users = parseUsers(); if(users.length==0){{alert('Cole usuários.');return;}}
          const peso = document.getElementById('peso').value || '1';
          const url = `/admin/assign_batch_generate?secret=${{secret}}&peso=${{encodeURIComponent(peso)}}&ras=${{encodeURIComponent(users.join(','))}}`;
          const r = await fetch(url); const j=await r.text(); document.getElementById('resultBox').textContent=j; refreshAll();
        }}
        async function poolAssign(){{
          const users = parseUsers(); if(users.length==0){{alert('Cole usuários.');return;}}
          const url = `/admin/assign_batch_use_pool?secret=${{secret}}&ras=${{encodeURIComponent(users.join(','))}}`;
          const r = await fetch(url); const j=await r.text(); document.getElementById('resultBox').textContent=j; refreshAll();
        }}
        async function refreshKeys(){{
          const r = await fetch(`/admin/keys_list?secret=${{secret}}`); const j = await r.json();
          const rows = Object.entries(j.keys||{{}}).map(([k,v])=>`<tr><td>${{k}}</td><td>${{v.used?'✔️':'—'}}</td><td>${{v.used_at||'—'}}</td><td>${{v.peso||1}}</td></tr>`).join('');
          document.getElementById('keysTable').innerHTML = `<table><thead><tr><th>Chave</th><th>Usada</th><th>Quando</th><th>Peso</th></tr></thead><tbody>${{rows}}</tbody></table>`;
        }}
        async function refreshPool(){{
          const r = await fetch(`/admin/pool_list?secret=${{secret}}`); const j = await r.json();
          const rows = (j.pool||[]).map(k=>`<tr><td>${{k}}</td></tr>`).join('');
          document.getElementById('poolTable').innerHTML = `<table><thead><tr><th>Chave livre</th></tr></thead><tbody>${{rows}}</tbody></table>`;
        }}
        async function refreshUsers(){{
          const r = await fetch(`/admin/users_list?secret=${{secret}}`); const j = await r.json();
          const rows = Object.entries(j.users||{{}}).map(([u,v])=>`<tr><td>${{u}}</td><td>${{v.key||'—'}}</td><td>${{v.used?'✔️':'—'}}</td><td>${{v.peso||1}}</td><td>${{(v.attempts&&v.attempts['{get_current_election_id()}'])||0}}</td></tr>`).join('');
          document.getElementById('usersTable').innerHTML = `<table><thead><tr><th>Usuário</th><th>Chave</th><th>Usou</th><th>Peso</th><th>Tentativas (EID atual)</th></tr></thead><tbody>${{rows}}</tbody></table>`;
        }}
        function refreshAll(){{ refreshKeys(); refreshPool(); refreshUsers(); }}
        refreshAll();
      </script>
    </body></html>
    """
    return Response(html, mimetype="text/html")
    # === APIs auxiliares usadas pela UI ===

@app.route("/admin/assign_batch_generate", methods=["GET","POST"])
def admin_assign_batch_generate():
    if not require_admin(request): abort(403)
    ras_param = (request.values.get("ras") or "").strip()
    if not ras_param:
        return Response('{"error":"informe ras=U1,U2,..."}', status=400, mimetype="application/json")
    try:
        peso = int(request.values.get("peso","1"))
    except:
        return Response('{"error":"peso inválido"}', status=400, mimetype="application/json")

    users = [r.strip() for r in ras_param.split(",") if r.strip()]
    users = list(dict.fromkeys(users))  # dedup

    keys_doc = load_keys()
    reg = load_registry()

    assigned = {}
    for uid in users:
        ent = reg["users"].get(uid, {"used": False, "peso": 1, "attempts": {}})
        if ent.get("key"):  # NÃO sobrescrever chave existente
            assigned[uid] = ent["key"]
            reg["users"][uid] = ent
            continue

        # gerar chave nova e única
        k = _mk_key()
        while k in keys_doc["keys"]:
            k = _mk_key()

        keys_doc["keys"][k] = {"used": False, "used_at": None, "peso": peso}
        ent["key"] = k
        reg["users"][uid] = ent
        assigned[uid] = k

    save_keys(keys_doc)
    save_registry(reg)
    return Response(json.dumps({"ok": True, "assigned": assigned}, ensure_ascii=False, indent=2),
                    mimetype="application/json")


@app.route("/admin/assign_batch_use_pool", methods=["GET","POST"])
def admin_assign_batch_use_pool():
    if not require_admin(request): abort(403)
    ras_param = (request.values.get("ras") or "").strip()
    if not ras_param:
        return Response('{"error":"informe ras=U1,U2,..."}', status=400, mimetype="application/json")

    users = [r.strip() for r in ras_param.split(",") if r.strip()]
    users = list(dict.fromkeys(users))

    keys_doc = load_keys()
    reg = load_registry()
    pool = _free_keys_from_pool()

    need = len([u for u in users if not reg["users"].get(u, {}).get("key")])
    if need > len(pool):
        return Response(json.dumps({"error":"chaves livres insuficientes","livres":len(pool)}, ensure_ascii=False),
                        status=409, mimetype="application/json")

    assigned = {}
    i = 0
    for uid in users:
        ent = reg["users"].get(uid, {"used": False, "peso": 1, "attempts": {}})
        if ent.get("key"):  # já tinha; mantém
            assigned[uid] = ent["key"]
            reg["users"][uid] = ent
            continue

        k = pool[i]; i += 1
        if k not in keys_doc["keys"] or keys_doc["keys"][k].get("used"):
            return Response('{"error":"inconsistência no pool"}', status=500, mimetype="application/json")

        ent["key"] = k
        reg["users"][uid] = ent
        assigned[uid] = k

    save_registry(reg)
    return Response(json.dumps({"ok": True, "assigned": assigned}, ensure_ascii=False, indent=2),
                    mimetype="application/json")


@app.route("/admin/keys_list")
def admin_keys_list():
    if not require_admin(request): abort(403)
    return Response(json.dumps(load_keys(), ensure_ascii=False, indent=2),
                    mimetype="application/json")


@app.route("/admin/pool_list")
def admin_pool_list():
    if not require_admin(request): abort(403)
    return Response(json.dumps({"pool": _free_keys_from_pool()}, ensure_ascii=False, indent=2),
                    mimetype="application/json")


@app.route("/admin/users_list")
def admin_users_list():
    if not require_admin(request): abort(403)
    return Response(json.dumps(load_registry(), ensure_ascii=False, indent=2),
                    mimetype="application/json")


# === Página admin com textarea + botões + tabelas ao vivo ===

@app.route("/admin/assign_ui")
def admin_assign_ui():
    if not require_admin(request): abort(403)
    secret = request.args.get("secret","")
    current_eid = get_current_election_id()

    html = f"""
<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <title>Admin · Atribuir chaves</title>
  <style>
    body{{font-family:system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; padding:24px; background:#f8fafc}}
    .wrap{{max-width:1100px;margin:0 auto}}
    h1{{margin:0 0 12px 0}}
    .card{{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:16px;margin:12px 0}}
    textarea{{width:100%;min-height:120px;padding:8px;border:1px solid #d1d5db;border-radius:10px}}
    .row{{display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin:10px 0}}
    input[type=number]{{width:120px;padding:8px;border:1px solid #d1d5db;border-radius:10px}}
    .btn{{padding:9px 12px;border-radius:10px;border:1px solid #111827;background:#111827;color:#fff;cursor:pointer}}
    .btn.alt{{background:#fff;color:#111827}}
    table{{border-collapse:collapse;width:100%}}
    th,td{{border:1px solid #e5e7eb;padding:6px;text-align:left;font-size:.95rem}}
    th{{background:#f3f4f6}}
    pre{{background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:10px;max-height:260px;overflow:auto}}
    .grid{{display:grid; gap:16px; grid-template-columns:1fr 1fr}}
    @media (max-width: 900px){{ .grid{{grid-template-columns:1fr}} }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Atribuir chaves (lote)</h1>
    <div class="card">
      <p>Cole aqui os <b>usuários</b> (um por linha). Ex.:</p>
      <pre>u20230001
u20230002
u20230003</pre>
      <textarea id="usersBox" placeholder="u1&#10;u2&#10;u3"></textarea>
      <div class="row">
        <label>Peso padrão: <input type="number" id="peso" value="1" min="1"></label>
        <button class="btn" onclick="genAssign()">Gerar e atribuir</button>
        <button class="btn alt" onclick="poolAssign()">Atribuir do pool</button>
      </div>
      <div>
        <b>Resultado:</b>
        <pre id="resultBox">(aguardando)</pre>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <h3>Chaves (voter_keys.json)</h3>
        <div id="keysTable">carregando...</div>
      </div>
      <div class="card">
        <h3>Pool (livres e não atribuídas)</h3>
        <div id="poolTable">carregando...</div>
      </div>
    </div>

    <div class="card">
      <h3>Usuários (user_registry.json)</h3>
      <div id="usersTable">carregando...</div>
    </div>
  </div>

  <script>
    const secret = {json.dumps(secret)};
    const currentEid = {json.dumps(current_eid)};

    function parseUsers() {{
      const t = document.getElementById('usersBox').value.trim();
      return t ? t.split(/\\r?\\n/).map(s=>s.trim()).filter(Boolean) : [];
    }}

    async function genAssign() {{
      const users = parseUsers(); if (!users.length) {{ alert('Cole usuários.'); return; }}
      const peso = document.getElementById('peso').value || '1';
      const url = `/admin/assign_batch_generate?secret=${{encodeURIComponent(secret)}}&peso=${{encodeURIComponent(peso)}}&ras=${{encodeURIComponent(users.join(','))}}`;
      const r = await fetch(url);
      document.getElementById('resultBox').textContent = await r.text();
      refreshAll();
    }}

    async function poolAssign() {{
      const users = parseUsers(); if (!users.length) {{ alert('Cole usuários.'); return; }}
      const url = `/admin/assign_batch_use_pool?secret=${{encodeURIComponent(secret)}}&ras=${{encodeURIComponent(users.join(','))}}`;
      const r = await fetch(url);
      document.getElementById('resultBox').textContent = await r.text();
      refreshAll();
    }}

    async function refreshKeys() {{
      const r = await fetch(`/admin/keys_list?secret=${{encodeURIComponent(secret)}}`);
      const j = await r.json();
      const rows = Object.entries(j.keys||{{}}).map(([k,v]) =>
        `<tr><td>${{k}}</td><td>${{v.used?'✔️':'—'}}</td><td>${{v.used_at||'—'}}</td><td>${{v.peso||1}}</td></tr>`
      ).join('');
      document.getElementById('keysTable').innerHTML =
        `<table><thead><tr><th>Chave</th><th>Usada</th><th>Quando</th><th>Peso</th></tr></thead><tbody>${{rows}}</tbody></table>`;
    }}

    async function refreshPool() {{
      const r = await fetch(`/admin/pool_list?secret=${{encodeURIComponent(secret)}}`);
      const j = await r.json();
      const rows = (j.pool||[]).map(k => `<tr><td>${{k}}</td></tr>`).join('');
      document.getElementById('poolTable').innerHTML =
        `<table><thead><tr><th>Chave livre</th></tr></thead><tbody>${{rows}}</tbody></table>`;
    }}

    async function refreshUsers() {{
      const r = await fetch(`/admin/users_list?secret=${{encodeURIComponent(secret)}}`);
      const j = await r.json();
      const rows = Object.entries(j.users||{{}}).map(([u,v]) =>
        `<tr><td>${{u}}</td><td>${{v.key||'—'}}</td><td>${{v.used?'✔️':'—'}}</td><td>${{v.peso||1}}</td><td>${{(v.attempts&&v.attempts[currentEid])||0}}</td></tr>`
      ).join('');
      document.getElementById('usersTable').innerHTML =
        `<table><thead><tr><th>Usuário</th><th>Chave</th><th>Usou</th><th>Peso</th><th>Tentativas (EID atual)</th></tr></thead><tbody>${{rows}}</tbody></table>`;
    }}

    function refreshAll() {{ refreshKeys(); refreshPool(); refreshUsers(); }}
    refreshAll();
  </script>
</body>
</html>
"""
    return Response(html, mimetype="text/html")
# ------------- Debug local -------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
