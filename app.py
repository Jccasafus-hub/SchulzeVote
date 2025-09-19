import os, json, uuid, secrets, string, hashlib, io, zipfile, csv
from pathlib import Path
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from typing import List, Dict, Tuple
from flask import (
    Flask, render_template, render_template_string, request, redirect, url_for,
    flash, Response, abort, session
)
from werkzeug.security import generate_password_hash, check_password_hash

# =============== App & Secrets ===============
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "mude-isto")

# Versão para cache busting (manifest/ícones/SW)
APP_VERSION = os.environ.get("APP_VERSION", datetime.utcnow().strftime("%Y%m%d%H%M%S"))
# Expõe para os templates Jinja (usado no base_admin.html e base.html)
app.jinja_env.globals['APP_VERSION'] = APP_VERSION

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "troque-admin")
ID_SALT      = os.environ.get("ID_SALT", "mude-este-salt")
app.config["ADMIN_SECRET"] = ADMIN_SECRET

# ===== Blueprint do Admin (opcional) =====
# Mantemos a tentativa de registrar um blueprint externo se existir,
# mas TODO o necessário está aqui no app.py para evitar 500/404.
try:
    from admin import admin_bp
    app.register_blueprint(admin_bp)
    print("[info] Admin blueprint registrado em /admin")
except Exception as e:
    print(f"[warn] Admin blueprint não registrado: {e}")

# =============== Arquivos & Pastas ===============
CAND_FILE       = "candidates.json"
VOTER_KEYS_FILE = "voter_keys.json"
ELECTION_FILE   = "election.json"
REGISTRY_FILE   = "user_registry.json"
TRASH_FILE      = "user_trash.json"

DATA_DIR  = Path("data")
BAL_DIR   = DATA_DIR / "ballots"
AUDIT_DIR = DATA_DIR / "audit"
BAL_DIR.mkdir(parents=True, exist_ok=True)
AUDIT_DIR.mkdir(parents=True, exist_ok=True)

# Candidatos especiais (sempre no fim da lista)
RESERVED_BLANK = "Voto em Branco"
RESERVED_NULL  = "Voto Nulo"

# =============== Utils ===============
def norm(s: str) -> str:
    return (s or "").strip().upper()

def _squash_spaces(s: str) -> str:
    return " ".join((s or "").strip().split())

def key_hash(k: str) -> str:
    return hashlib.sha256((ID_SALT + norm(k)).encode()).hexdigest()

def require_admin(req):
    token = req.args.get("secret") or req.headers.get("X-Admin-Secret")
    return (ADMIN_SECRET and token == ADMIN_SECRET)

def _read_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def _write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# =============== Persistência de domínio ===============
def load_candidates() -> List[str]:
    data = _read_json(CAND_FILE, [])
    # Garante os reservados no fim (sem duplicar)
    base = [c for c in data if c not in (RESERVED_BLANK, RESERVED_NULL)]
    base = [_squash_spaces(c) for c in base if c]
    # remove vazios e dupes preservando ordem
    seen = set()
    clean = []
    for c in base:
        if c not in seen:
            seen.add(c)
            clean.append(c)
    # adiciona especiais
    if RESERVED_BLANK not in clean:
        clean.append(RESERVED_BLANK)
    if RESERVED_NULL not in clean:
        clean.append(RESERVED_NULL)
    return clean

def save_candidates(lines: List[str]):
    # Salva só a lista “core”; reservados serão re-adicionados via load_candidates()
    core = []
    seen = set()
    for ln in lines:
        ln = _squash_spaces(ln)
        if not ln:
            continue
        if ln in (RESERVED_BLANK, RESERVED_NULL):
            continue
        if ln not in seen:
            seen.add(ln)
            core.append(ln)
    _write_json(CAND_FILE, core)

def load_keys():
    """Estrutura: {"keys": {<key>: {"used": bool, "used_at": iso?, "peso": int}}}"""
    d = _read_json(VOTER_KEYS_FILE, {})
    d.setdefault("keys", {})
    return d

def save_keys(d):
    if "keys" not in d:
        d = {"keys": d}
    _write_json(VOTER_KEYS_FILE, d)

def load_registry():
    """Estrutura: {"users": {<user_id>: {"pwd_hash": str, "used": bool, "peso": int, "attempts": {eid: int}, "key": str?}}}"""
    d = _read_json(REGISTRY_FILE, {})
    d.setdefault("users", {})
    return d

def save_registry(d):
    if "users" not in d:
        d = {"users": d}
    _write_json(REGISTRY_FILE, d)

def load_trash():
    d = _read_json(TRASH_FILE, {})
    d.setdefault("users", {})
    return d

def save_trash(d):
    if "users" not in d:
        d = {"users": d}
    _write_json(TRASH_FILE, d)

# =============== Election (id, prazo, meta) ===============
def load_election_doc():
    d = _read_json(ELECTION_FILE, {})
    d.setdefault("election_id", "default")
    d.setdefault("deadline_utc", None)
    d.setdefault("meta", {})  # meta[eid] = {title, date, time, tz, category, updated_at}
    return d

def save_election_doc(d):
    _write_json(ELECTION_FILE, d)

def get_current_election_id():
    return load_election_doc().get("election_id", "default")

def set_current_election_id(eid: str):
    d = load_election_doc()
    d["election_id"] = eid
    save_election_doc(d)

def set_election_meta(eid: str, title: str, date_s: str, time_s: str, tz_s: str, category: str = ""):
    d = load_election_doc()
    d["meta"][eid] = {
        "title": (title or "").strip(),
        "date": (date_s or "").strip(),
        "time": (time_s or "").strip(),
        "tz":   (tz_s or "America/Sao_Paulo").strip(),
        "category": (category or "").strip(),
        "updated_at": datetime.utcnow().isoformat() + "Z"
    }
    save_election_doc(d)

def get_election_meta(eid: str):
    return load_election_doc().get("meta", {}).get(eid, None)

def load_deadline():
    iso = load_election_doc().get("deadline_utc")
    if not iso:
        return None
    try:
        return datetime.fromisoformat(iso)
    except Exception:
        return None

def save_deadline(dt_utc):
    d = load_election_doc()
    d["deadline_utc"] = None if dt_utc is None else dt_utc.astimezone(timezone.utc).isoformat()
    save_election_doc(d)

def is_voting_open():
    dl = load_deadline()
    if dl is None:
        return True
    return datetime.now(timezone.utc) < dl

# =============== Auditoria & Cédulas ===============
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

def audit_admin(eid: str, action: str, detail: str, ip: str = "-"):
    ts = datetime.utcnow().isoformat() + "Z"
    audit_line(eid, f"ADMIN {action} {ts} {detail} by_ip={ip}")

# =============== Schulze (cálculo de ranking) ===============
def _pairwise_from_ballots(ballots: List[dict], candidates: List[str]) -> Dict[str, Dict[str, int]]:
    # Constrói matriz P[a][b] = número (peso) de votos que preferem a sobre b
    P = {a: {b: 0 for b in candidates if b != a} for a in candidates}
    # Para cada cédula: ranks[c] = inteiro 1..N (menor é melhor) ou None
    for b in ballots:
        peso = int(b.get("peso", 1))
        ranks = b.get("ranks", {})
        # Considera somente candidatos presentes
        for a in candidates:
            for c in candidates:
                if a == c: 
                    continue
                ra = ranks.get(a, None)
                rc = ranks.get(c, None)
                # Preferência: número menor significa preferência maior
                # Empates/ausentes (None) não contam
                if isinstance(ra, int) and isinstance(rc, int):
                    if ra < rc:
                        P[a][c] += peso
    return P

def schulze_ranking_from_ballots(ballots: List[dict], candidates: List[str]) -> Tuple[List[str], Dict[str, Dict[str, int]], Dict[str, Dict[str, int]]]:
    """
    Retorna:
      ranking (lista do melhor ao pior),
      pairwise P[a][b],
      strongest_path S[a][b]
    Implementação padrão do método de Schulze (Schulze beatpath).
    """
    # Remove reservados da matriz pairwise, mas mantemos candidatos completos para exibir se necessário
    core_cands = [c for c in candidates if c not in (RESERVED_BLANK, RESERVED_NULL)]
    if not core_cands:
        return [], {}, {}

    P = _pairwise_from_ballots(ballots, core_cands)

    # Strength of strongest paths
    S = {a: {b: 0 for b in core_cands} for a in core_cands}
    for a in core_cands:
        for b in core_cands:
            if a == b: 
                continue
            if P[a][b] > P[b][a]:
                S[a][b] = P[a][b]
            else:
                S[a][b] = 0
    # Floyd–Warshall-like update
    for i in core_cands:
        for j in core_cands:
            if i == j: 
                continue
            for k in core_cands:
                if i == k or j == k:
                    continue
                S[j][k] = max(S[j][k], min(S[j][i], S[i][k]))

    # Ordenação por Schulze: a precede b se S[a][b] > S[b][a]
    def _cmp(a, b):
        if a == b:
            return 0
        if S[a][b] > S[b][a]:
            return -1
        if S[a][b] < S[b][a]:
            return 1
        # Empate: fallback lexicográfico estável
        return -1 if a.lower() < b.lower() else (1 if a.lower() > b.lower() else 0)

    # Python 3 não tem cmp nativo; simulamos com key usando functools.cmp_to_key
    from functools import cmp_to_key
    ranked_core = sorted(core_cands, key=cmp_to_key(_cmp))

    return ranked_core, P, S

# =============== Rotas Públicas (núcleo) ===============
@app.route("/")
def index():
    return render_template("index.html", get_current_election_id=get_current_election_id)

# Guia do método de Schulze (template dedicado)
@app.route("/schulze_guide")
def schulze_guide():
    # Apenas renderiza o template; todo o conteúdo está em templates/schulze_guide.html
    return render_template("schulze_guide.html")

# Alias para compatibilidade: /schulze -> /schulze_guide
@app.route("/schulze")
def schulze_alias():
    return redirect(url_for("schulze_guide"))

# =============== Registro/Login básico (opcional) ===============
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        user_id = (request.form.get("user_id") or "").strip()
        pw  = (request.form.get("password") or "").strip()
        pw2 = (request.form.get("password2") or "").strip()
        if not user_id or not pw or not pw2:
            flash("Preencha usuário e senha (2x).", "error")
            return redirect(url_for("register"))
        if pw != pw2:
            flash("As senhas não conferem.", "error")
            return redirect(url_for("register"))
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
            flash("Usuário ou senha inválidos.", "error")
            return redirect(url_for("login"))
        session["user_id"] = user_id
        flash("Login realizado.", "success")
        return redirect(url_for("vote"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("Você saiu.", "info")
    return redirect(url_for("index"))

# Helpers de voto
def parse_numeric_form_to_ranks(form, candidates):
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
        if not r or str(r).strip() == "":
            ranks[c] = None
        else:
            try:
                n = int(str(r).strip())
                ranks[c] = n if n >= 1 else None
            except Exception:
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
    if not is_voting_open():
        return Response(
            "<h2>Votação encerrada</h2><p>O prazo expirou.</p><p><a href='/'>Início</a></p>",
            mimetype="text/html",
            status=403
        )

    candidates = load_candidates()
    if request.method == "POST":
        user_id = session.get("user_id")
        if not user_id:
            flash("Faça login para votar.", "error")
            return redirect(url_for("login"))

        voter_key = norm(request.form.get("voter_id", ""))
        if not voter_key:
            flash("Informe sua CHAVE de votação.", "error")
            return redirect(url_for("vote"))

        reg = load_registry()
        entry = reg.get("users", {}).get(user_id)
        if not entry:
            flash("Usuário não habilitado.", "error")
            return redirect(url_for("login"))

        expected_key = (entry or {}).get("key")
        if not expected_key:
            flash("Seu usuário ainda não tem uma chave atribuída.", "error")
            return redirect(url_for("index"))

        eid = get_current_election_id()
        current_attempts = int(entry.get("attempts", {}).get(eid, 0))
        if current_attempts >= 5:
            flash("Limite de tentativas de chave atingido para esta votação.", "error")
            audit_line(eid, f"ATTEMPT-LIMIT {datetime.utcnow().isoformat()}Z user={user_id} ip={request.remote_addr or '-'}")
            return redirect(url_for("index"))

        if voter_key != expected_key:
            n = _inc_attempt(user_id, eid)
            flash("Chave inválida para este usuário.", "error")
            audit_line(
                eid,
                f"ATTEMPT {datetime.utcnow().isoformat()}Z user={user_id} provided={voter_key} ip={request.remote_addr or '-'} count={n}"
            )
            return redirect(url_for("vote"))

        # verifica chave no pool
        keys_doc = load_keys()
        kinfo = keys_doc["keys"].get(voter_key)
        if not kinfo:
            flash("Chave inexistente.", "error")
            return redirect(url_for("vote"))
        if kinfo.get("used"):
            flash("Esta chave já foi usada.", "error")
            return redirect(url_for("index"))

        # monta ranks
        posted_ranking = request.form.getlist("ranking")
        if posted_ranking:
            ranks = {c: None for c in candidates}
            r = 1
            for c in posted_ranking:
                if c in candidates and ranks[c] is None:
                    ranks[c] = r
                    r += 1
        else:
            ranks = parse_numeric_form_to_ranks(request.form, candidates)

        if not any((isinstance(v, int) and v >= 1) for v in ranks.values()):
            flash("Nenhuma preferência informada.", "error")
            return redirect(url_for("vote"))

        # peso final: peso do usuário > peso da chave > 1
        peso = int(entry.get("peso", kinfo.get("peso", 1)))

        # marca chave usada
        kinfo["used"] = True
        kinfo["used_at"] = datetime.utcnow().isoformat() + "Z"
        keys_doc["keys"][voter_key] = kinfo
        save_keys(keys_doc)

        # marca usuário usado; zera tentativas nesta eleição
        entry["used"] = True
        atts = entry.get("attempts", {})
        atts[eid] = 0
        entry["attempts"] = atts
        reg["users"][user_id] = entry
        save_registry(reg)

        # salva cédula
        voter_key_h = key_hash(voter_key)
        append_ballot(eid, {"ranks": ranks, "peso": peso, "voter": voter_key_h})

        # recibo
        receipt = str(uuid.uuid4())
        audit_line(
            eid,
            f"VOTE {datetime.utcnow().isoformat()}Z voter={voter_key_h} receipt={receipt} ip={request.remote_addr or '-'}"
        )

        return render_template("receipt.html", receipt=receipt, eid=eid)

    # GET
    return render_template("vote.html", candidates=candidates)

# =============== Resultados & Auditoria pública ===============
@app.route("/results")
def results_current():
    return redirect(url_for("public_results", eid=get_current_election_id()))

@app.route("/public/<eid>/results")
def public_results(eid):
    ballots = load_ballots(eid)
    meta = get_election_meta(eid)
    if not ballots:
        return render_template(
            "results.html",
            ranking=[], empty=True, total_votos=0,
            election_id=eid, election_meta=meta
        )
    try:
        candidates = load_candidates()
        ranking, pairwise, strength = schulze_ranking_from_ballots(ballots, candidates)
        return render_template(
            "results.html",
            ranking=ranking, empty=False,
            total_votos=sum(int(b.get("peso", 1)) for b in ballots),
            election_id=eid, election_meta=meta,
            candidates=candidates if request.args.get("debug") == "1" else None,
            pairwise=pairwise if request.args.get("debug") == "1" else None,
            strength=strength if request.args.get("debug") == "1" else None
        )
    except Exception as e:
        return Response(f"Erro ao calcular resultados: {e}", status=500)

@app.route("/public/<eid>/audit")
def public_audit(eid):
    p = audit_path(eid)
    meta = get_election_meta(eid)
    if meta:
        head = (
            "<h1>%s</h1><p><b>ID:</b> %s%s</p>" % (
                meta.get('title', 'Auditoria'),
                eid,
                (" • <b>Data/Hora:</b> %s %s %s" % (meta.get('date',''), meta.get('time',''), meta.get('tz','')))
                if meta.get('date') and meta.get('time') else ""
            )
        )
    else:
        head = "<h1>Auditoria</h1><p><b>ID:</b> %s</p>" % eid
    if not p.exists():
        return Response(head + "<pre>(Sem auditoria para esta votação.)</pre>", mimetype="text/html")
    with open(p, "r", encoding="utf-8") as f:
        lines = f.readlines()
    return Response(head + "<pre>" + "".join(lines) + "</pre>", mimetype="text/html")

# =============== /public/elections (metadados + filtros + CSV) ===============
@app.route("/public/elections")
def public_elections():
    q = request.args
    flat = q.get("flat") == "1"
    cat_filter = (q.get("category") or "").strip().lower()
    start = (q.get("start") or "").strip()
    end   = (q.get("end") or "").strip()

    metas = load_election_doc().get("meta", {})
    file_eids = [p.stem for p in BAL_DIR.glob("*.json")]
    all_eids = sorted(set(list(metas.keys()) + file_eids))

    if flat:
        return Response(json.dumps({"elections": all_eids}, ensure_ascii=False, indent=2), mimetype="application/json")

    def within_date(m):
        d = (m.get("date") or "").strip()
        if not d:
            return True
        if start and d < start:
            return False
        if end and d > end:
            return False
        return True

    enriched = []
    for eid in all_eids:
        m = metas.get(eid, {})
        cat = (m.get("category", "") or "").strip()
        if cat_filter and cat.lower() != cat_filter:
            continue
        if not within_date(m):
            continue
        enriched.append({
            "eid": eid,
            "title": m.get("title", ""),
            "date":  m.get("date", ""),
            "time":  m.get("time", ""),
            "tz":    m.get("tz", ""),
            "category": cat
        })

    enriched.sort(key=lambda x: x.get("date", ""), reverse=True)
    return Response(json.dumps({"elections": enriched}, ensure_ascii=False, indent=2), mimetype="application/json")

@app.route("/public/elections.csv")
def public_elections_csv():
    r = app.test_client().get("/public/elections", query_string=request.args)
    data = json.loads(r.get_data(as_text=True))
    rows = data.get("elections", [])
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["eid","title","date","time","tz","category"])
    for it in rows:
        w.writerow([
            it.get("eid",""),
            it.get("title",""),
            it.get("date",""),
            it.get("time",""),
            it.get("tz",""),
            it.get("category","")
        ])
    resp = Response(out.getvalue(), mimetype="text/csv")
    resp.headers["Content-Disposition"] = 'attachment; filename="elections.csv"'
    return resp

# =============== Relatórios extras CSV ===============
def make_csv_ranking(ranking, total_weight):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["posicao", "candidato"])
    for i, c in enumerate(ranking, start=1):
        w.writerow([i, c])
    w.writerow([])
    w.writerow(["total_peso", total_weight])
    return out.getvalue()

def make_csv_pairwise(P, candidates):
    out = io.StringIO()
    w = csv.writer(out)
    header = ["candidate"] + candidates
    w.writerow(header)
    for a in candidates:
        row = [a] + [P[a].get(b, 0) if a != b else "" for b in candidates]
        w.writerow(row)
    return out.getvalue()

@app.route("/public/<eid>/results.csv")
def public_results_csv(eid):
    ballots = load_ballots(eid)
    if not ballots:
        csv_text = "posicao,candidato\n"
        return Response(csv_text, mimetype="text/csv")
    candidates = load_candidates()
    ranking, pairwise, strength = schulze_ranking_from_ballots(ballots, candidates)
    total_weight = sum(int(b.get("peso", 1)) for b in ballots)
    csv_text = make_csv_ranking(ranking, total_weight)
    resp = Response(csv_text, mimetype="text/csv")
    resp.headers["Content-Disposition"] = f'attachment; filename="results_{eid}.csv"'
    return resp

@app.route("/public/<eid>/pairwise.csv")
def public_pairwise_csv(eid):
    ballots = load_ballots(eid)
    candidates = load_candidates()
    if not ballots:
        header = "candidate," + ",".join([c for c in candidates if c not in (RESERVED_BLANK, RESERVED_NULL)])
        return Response(header + "\n", mimetype="text/csv")
    # gera pairwise apenas para candidatos "core"
    core = [c for c in candidates if c not in (RESERVED_BLANK, RESERVED_NULL)]
    _, pairwise, _ = schulze_ranking_from_ballots(ballots, candidates)
    # pairwise veio apenas com core; garante ordem do header
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["candidate"] + core)
    for a in core:
        row = [a] + [pairwise[a].get(b, 0) if a != b else "" for b in core]
        w.writerow(row)
    resp = Response(out.getvalue(), mimetype="text/csv")
    resp.headers["Content-Disposition"] = f'attachment; filename="pairwise_{eid}.csv"'
    return resp

# ---------- Helpers específicos de Admin ----------

def _ensure_keys_doc():
    doc = _read_json(VOTER_KEYS_FILE, {})
    doc.setdefault("keys", {})   # "KEY": {"used":false,"used_at":null,"peso":1}
    doc.setdefault("pool", [])   # lista de chaves livres (strings)
    return doc

def load_keys():
    return _ensure_keys_doc()

def save_keys(doc):
    _write_json(VOTER_KEYS_FILE, doc)

def _ensure_registry():
    reg = _read_json(REGISTRY_FILE, {})
    reg.setdefault("users", {})  # "user": {"pwd_hash":..., "key": "...", "used":false, "peso":1, "attempts":{eid:n}}
    return reg

def load_registry():
    return _ensure_registry()

def save_registry(reg):
    _write_json(REGISTRY_FILE, reg)

def load_trash():
    return _read_json(TRASH_FILE, {"users":{}})

def save_trash(t):
    _write_json(TRASH_FILE, t)

def _ensure_candidates_doc(lst):
    # Normaliza, remove vazios e duplica “Branco/Nulo” no fim
    base = [_squash_spaces(x) for x in lst if _squash_spaces(x)]
    base = [x for x in base if x not in (RESERVED_BLANK, RESERVED_NULL)]
    base = list(dict.fromkeys(base))  # únicos preservando ordem
    base += [RESERVED_BLANK, RESERVED_NULL]
    return base

def load_candidates():
    return _read_json(CAND_FILE, [RESERVED_BLANK, RESERVED_NULL])

def save_candidates(lst):
    _write_json(CAND_FILE, _ensure_candidates_doc(lst))

# ---------- Páginas Admin (UI) ----------

@app.route("/admin/assign_ui")
def admin_assign_ui():
    if not require_admin(request): abort(403)
    return render_template(
        "admin_assign_ui.html",
        secret=(request.args.get("secret") or ""),
        current_eid=get_current_election_id()
    )

@app.route("/admin/audit_preview")
def admin_audit_preview():
    if not require_admin(request): abort(403)
    return render_template(
        "admin_audit_preview.html",
        secret=(request.args.get("secret") or ""),
        current_eid=get_current_election_id()
    )

# ---------- JSON: chaves, pool, usuários, lixeira ----------

@app.route("/admin/keys_list")
def admin_keys_list():
    if not require_admin(request): abort(403)
    doc = load_keys()
    return Response(json.dumps({"keys": doc.get("keys", {})}, ensure_ascii=False, indent=2), mimetype="application/json")

@app.route("/admin/pool_list")
def admin_pool_list():
    if not require_admin(request): abort(403)
    doc = load_keys()
    return Response(json.dumps({"pool": doc.get("pool", [])}, ensure_ascii=False, indent=2), mimetype="application/json")

@app.route("/admin/users_list")
def admin_users_list():
    if not require_admin(request): abort(403)
    reg = load_registry()
    return Response(json.dumps({"users": reg.get("users", {})}, ensure_ascii=False, indent=2), mimetype="application/json")

@app.route("/admin/trash_list")
def admin_trash_list():
    if not require_admin(request): abort(403)
    t = load_trash()
    return Response(json.dumps({"users": t.get("users", {})}, ensure_ascii=False, indent=2), mimetype="application/json")

# ---------- Atribuição de chaves (gerar ou usar pool), pesos, exclusões ----------

def _assign_key_to_user(reg, keys_doc, user, key, peso=None):
    u = reg["users"].get(user, {"used": False, "peso": 1, "attempts": {}})
    u["key"] = key
    if peso is not None:
        u["peso"] = int(peso)
    reg["users"][user] = u
    # garante presença no mapa de keys
    kinfo = keys_doc["keys"].get(key, {})
    kinfo.setdefault("used", False)
    if peso is not None:
        kinfo["peso"] = int(peso)
    keys_doc["keys"][key] = kinfo

@app.route("/admin/assign_batch_generate")
def admin_assign_batch_generate():
    if not require_admin(request): abort(403)
    ras  = (request.args.get("ras") or "").strip()
    peso = int(request.args.get("peso") or "1")
    if not ras:
        return Response("informe ?ras=user1,user2,...", status=400)
    users = [u for u in ras.split(",") if u.strip()]
    reg = load_registry()
    keys_doc = load_keys()

    def gen_key():
        # Formato: XXXX-YYYY-ZZZZ (alfanum)
        alphabet = string.ascii_uppercase + string.digits
        parts = []
        for _ in range(3):
            parts.append("".join(secrets.choice(alphabet) for _ in range(4)))
        return "-".join(parts)

    assigned = []
    for u in users:
        # gera chaves até achar uma inédita
        for _ in range(1000):
            k = gen_key()
            if k not in keys_doc["keys"] and k not in keys_doc.get("pool", []):
                _assign_key_to_user(reg, keys_doc, u, k, peso=peso)
                assigned.append((u, k))
                break

    save_registry(reg); save_keys(keys_doc)
    # auditoria
    eid = get_current_election_id()
    audit_admin(eid, "ASSIGN_GENERATE", f"count={len(assigned)}", request.remote_addr or "-")

    # resposta texto simples
    lines = [f"{u},{k}" for (u, k) in assigned]
    return Response("\n".join(lines) if lines else "(nada a atribuir)", mimetype="text/plain; charset=utf-8")

@app.route("/admin/assign_batch_use_pool")
def admin_assign_batch_use_pool():
    if not require_admin(request): abort(403)
    ras = (request.args.get("ras") or "").strip()
    if not ras:
        return Response("informe ?ras=user1,user2,...", status=400)
    users = [u for u in ras.split(",") if u.strip()]
    reg = load_registry()
    keys_doc = load_keys()
    pool = keys_doc.get("pool", [])

    assigned = []
    for u in users:
        if not pool:
            break
        k = pool.pop(0)
        _assign_key_to_user(reg, keys_doc, u, k)
        assigned.append((u, k))

    keys_doc["pool"] = pool
    save_registry(reg); save_keys(keys_doc)
    eid = get_current_election_id()
    audit_admin(eid, "ASSIGN_FROM_POOL", f"count={len(assigned)}", request.remote_addr or "-")

    lines = [f"{u},{k}" for (u, k) in assigned]
    return Response("\n".join(lines) if lines else "(pool esgotado ou nada a atribuir)", mimetype="text/plain; charset=utf-8")

@app.route("/admin/set_user_weight")
def admin_set_user_weight():
    if not require_admin(request): abort(403)
    user = (request.args.get("user") or "").strip()
    peso = int(request.args.get("peso") or "1")
    if not user:
        return Response('{"error":"user"}', status=400, mimetype="application/json")
    reg = load_registry()
    u = reg.get("users", {}).get(user)
    if not u:
        return Response('{"error":"usuario_nao_encontrado"}', status=404, mimetype="application/json")
    u["peso"] = max(1, int(peso))
    reg["users"][user] = u
    save_registry(reg)
    eid = get_current_election_id()
    audit_admin(eid, "SET_USER_WEIGHT", f"user={user} peso={u['peso']}", request.remote_addr or "-")
    return Response('{"ok":true}', mimetype="application/json")

@app.route("/admin/delete_user")
def admin_delete_user():
    if not require_admin(request): abort(403)
    user = (request.args.get("user") or "").strip()
    if not user:
        return Response('{"error":"user"}', status=400, mimetype="application/json")
    reg = load_registry()
    u = reg.get("users", {}).pop(user, None)
    if not u:
        return Response('{"error":"usuario_nao_encontrado"}', status=404, mimetype="application/json")
    save_registry(reg)
    t = load_trash()
    u["deleted_at"] = datetime.utcnow().isoformat() + "Z"
    t.setdefault("users", {})[user] = u
    save_trash(t)
    eid = get_current_election_id()
    audit_admin(eid, "DELETE_USER", f"user={user}", request.remote_addr or "-")
    return Response('{"ok":true}', mimetype="application/json")

@app.route("/admin/delete_users_batch")
def admin_delete_users_batch():
    if not require_admin(request): abort(403)
    users_q = (request.args.get("users") or "").strip()
    if not users_q:
        return Response('{"error":"users"}', status=400, mimetype="application/json")
    users = [u for u in users_q.split(",") if u.strip()]
    reg = load_registry()
    t = load_trash()
    moved = 0
    for u in users:
        item = reg.get("users", {}).pop(u, None)
        if item:
            item["deleted_at"] = datetime.utcnow().isoformat() + "Z"
            t.setdefault("users", {})[u] = item
            moved += 1
    save_registry(reg); save_trash(t)
    eid = get_current_election_id()
    audit_admin(eid, "DELETE_USERS_BATCH", f"count={moved}", request.remote_addr or "-")
    return Response(json.dumps({"ok": True, "moved": moved}, ensure_ascii=False), mimetype="application/json")

@app.route("/admin/restore_user")
def admin_restore_user():
    if not require_admin(request): abort(403)
    user = (request.args.get("user") or "").strip()
    if not user:
        return Response('{"error":"user"}', status=400, mimetype="application/json")
    t = load_trash()
    item = t.get("users", {}).pop(user, None)
    if not item:
        return Response('{"error":"nao_encontrado"}', status=404, mimetype="application/json")
    reg = load_registry()
    item.pop("deleted_at", None)
    reg.setdefault("users", {})[user] = item
    save_trash(t); save_registry(reg)
    eid = get_current_election_id()
    audit_admin(eid, "RESTORE_USER", f"user={user}", request.remote_addr or "-")
    return Response('{"ok":true}', mimetype="application/json")

@app.route("/admin/empty_trash", methods=["POST"])
def admin_empty_trash():
    if not require_admin(request): abort(403)
    save_trash({"users":{}})
    eid = get_current_election_id()
    audit_admin(eid, "EMPTY_TRASH", "ok", request.remote_addr or "-")
    return Response('{"ok":true}', mimetype="application/json")

# ---------- Downloads para Admin (ZIPs e bundle) ----------

def _sha256_file(path: Path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

@app.route("/admin/export_audit_bundle")
def admin_export_audit_bundle():
    if not require_admin(request): abort(403)
    eid = (request.args.get("eid") or get_current_election_id()).strip()

    paths = []
    bpath = ballots_path(eid)
    apath = audit_path(eid)
    if bpath.exists():
        paths.append(("ballots/" + bpath.name, bpath))
    if apath.exists():
        paths.append(("audit/" + apath.name, apath))
    for name in [CAND_FILE, ELECTION_FILE, VOTER_KEYS_FILE, REGISTRY_FILE, TRASH_FILE]:
        p = Path(name)
        if p.exists():
            paths.append(("config/" + p.name, p))

    manifest = {
        "eid": eid,
        "generated_at_utc": datetime.utcnow().isoformat() + "Z",
        "files": []
    }
    for arcname, p in paths:
        try:
            manifest["files"].append({
                "arcname": arcname,
                "size": p.stat().st_size,
                "sha256": _sha256_file(p)
            })
        except Exception as e:
            manifest["files"].append({"arcname": arcname, "error": f"{e}"})

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for arcname, p in paths:
            z.write(p, arcname)
        z.writestr("README.txt",
            "SchulzeVote - Pacote de Auditoria\n"
            f"EID: {eid}\n"
            "- ballots/<eid>.json: cédulas (anônimas)\n"
            "- audit/<eid>.log: log textual\n"
            "- config/*.json: configs e registros\n"
            "Veja MANIFEST.json (SHA-256) para integridade.\n"
        )
        z.writestr("MANIFEST.json", json.dumps(manifest, ensure_ascii=False, indent=2))
    buf.seek(0)
    resp = Response(buf.getvalue(), mimetype="application/zip")
    resp.headers["Content-Disposition"] = f'attachment; filename="audit_bundle_{eid}.zip"'
    return resp

@app.route("/admin/backup_zip")
def admin_backup_zip():
    if not require_admin(request): abort(403)
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        def add_if_exists(path, arcname=None):
            if os.path.exists(path):
                z.write(path, arcname or path)
        for fname in [CAND_FILE, ELECTION_FILE, VOTER_KEYS_FILE, REGISTRY_FILE, TRASH_FILE]:
            add_if_exists(fname, fname)
        # data/*
        if DATA_DIR.exists():
            for root, _, files in os.walk(DATA_DIR):
                for f in files:
                    full = os.path.join(root, f)
                    rel  = os.path.relpath(full, start=str(DATA_DIR))
                    z.write(full, os.path.join("data", rel))
    buf.seek(0)
    resp = Response(buf.getvalue(), mimetype="application/zip")
    resp.headers["Content-Disposition"] = f'attachment; filename="schulzevote_backup_{ts}.zip"'
    return resp

@app.route("/admin/backup_zip_eid")
def admin_backup_zip_eid():
    if not require_admin(request): abort(403)
    eid = (request.args.get("eid") or "").strip()
    if not eid:
        return Response('{"error":"informe ?eid=..."}', status=400, mimetype="application/json")

    ballots_file = ballots_path(eid)
    audit_file   = audit_path(eid)
    meta = get_election_meta(eid) or {}
    context = {"eid": eid, "meta": meta, "candidates_snapshot": load_candidates()}

    ballots_exists = ballots_file.exists()
    audit_exists   = audit_file.exists()
    if not ballots_exists and not audit_exists:
        return Response(json.dumps({"error": "nenhum arquivo encontrado para este EID"}, ensure_ascii=False),
                        status=404, mimetype="application/json")

    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        if ballots_exists: z.write(str(ballots_file), f"data/ballots/{eid}.json")
        if audit_exists:   z.write(str(audit_file),   f"data/audit/{eid}.log")
        z.writestr(f"meta/election_meta_{eid}.json", json.dumps(context, ensure_ascii=False, indent=2))
        if os.path.exists(ELECTION_FILE): z.write(ELECTION_FILE, "election.json")
    buf.seek(0)
    resp = Response(buf.getvalue(), mimetype="application/zip")
    resp.headers["Content-Disposition"] = f'attachment; filename="schulzevote_eid_{eid}_{ts}.zip"'
    return resp

# ---------- Dados crus para Admin (usados pelo preview) ----------

@app.route("/admin/audit_raw")
def admin_audit_raw():
    if not require_admin(request): abort(403)
    eid = (request.args.get("eid") or get_current_election_id()).strip()
    p = audit_path(eid)
    meta = get_election_meta(eid)
    if not p.exists():
        return Response(json.dumps({"eid": eid, "meta": meta, "lines": []}, ensure_ascii=False, indent=2), mimetype="application/json")
    with open(p, "r", encoding="utf-8") as f:
        lines = [ln.rstrip("\n") for ln in f.readlines()]
    return Response(json.dumps({"eid": eid, "meta": meta, "lines": lines}, ensure_ascii=False, indent=2), mimetype="application/json")

@app.route("/admin/ballots_raw")
def admin_ballots_raw():
    if not require_admin(request): abort(403)
    eid = (request.args.get("eid") or get_current_election_id()).strip()
    ballots = load_ballots(eid)
    return Response(json.dumps({"eid": eid, "ballots": ballots}, ensure_ascii=False, indent=2), mimetype="application/json")

@app.route("/admin/ping")
def admin_ping():
    ok = require_admin(request)
    return Response(json.dumps({"ok": ok}, ensure_ascii=False), status=200 if ok else 403, mimetype="application/json")

# ---------- Debug local ----------
if __name__ == "__main__":
    # Em produção, o servidor (gunicorn) importa app:app (ver Procfile).
    app.run(host="0.0.0.0", port=5000, debug=True)
