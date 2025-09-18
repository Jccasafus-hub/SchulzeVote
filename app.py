import os, json, uuid, secrets, string, hashlib, io, zipfile, csv
from pathlib import Path
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
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
# Expõe para os templates Jinja (usado no base_admin.html)
app.jinja_env.globals['APP_VERSION'] = APP_VERSION

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "troque-admin")
ID_SALT      = os.environ.get("ID_SALT", "mude-este-salt")

# ===== Blueprint do Admin (login/home/logout sob /admin) =====
# Certifique-se de ter criado: admin/__init__.py e admin/views.py (que definem admin_bp)
try:
    from admin import admin_bp
    app.register_blueprint(admin_bp)
except Exception as e:
    # Se o blueprint ainda não existir, o app continua funcionando sem as rotas /admin/login e /admin/logout.
    # A rota /admin/home NÃO é registrada aqui para evitar conflitos.
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
    # Compatível com fluxo atual: ?secret=... ou header X-Admin-Secret
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

# =============== Candidatos ===============
def _default_candidates():
    return ["Alice", "Bob", "Charlie", RESERVED_BLANK, RESERVED_NULL]

def normalize_candidates(user_list):
    def is_reserved(name: str) -> bool:
        n = _squash_spaces(name).casefold()
        return n in (RESERVED_BLANK.casefold(), RESERVED_NULL.casefold())
    seen = set()
    cleaned = []
    for c in (user_list or []):
        c = _squash_spaces(c)
        if not c:
            continue
        if is_reserved(c):
            continue
        k = c.casefold()
        if k in seen:
            continue
        seen.add(k)
        cleaned.append(c)
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

# =============== Chaves & Registro ===============
def load_keys():
    d = _read_json(VOTER_KEYS_FILE, {"keys": {}})
    for k, v in list(d.get("keys", {}).items()):
        v.setdefault("used", False)
        v.setdefault("used_at", None)
        v.setdefault("peso", 1)
    return d

def save_keys(d):
    _write_json(VOTER_KEYS_FILE, d)

def load_registry():
    d = _read_json(REGISTRY_FILE, {"users": {}})
    # users[user] = { key, used, pwd_hash, peso, attempts{eid:int} }
    for u, v in list(d.get("users", {}).items()):
        v.setdefault("used", False)
        v.setdefault("peso", 1)
        v.setdefault("attempts", {})
    return d

def save_registry(d):
    _write_json(REGISTRY_FILE, d)

# =============== Lixeira (soft delete) ===============
def load_trash():
    return _read_json(TRASH_FILE, {"users": {}})

def save_trash(d):
    _write_json(TRASH_FILE, d)

def move_user_to_trash(uid: str, entry: dict):
    trash = load_trash()
    entry_copy = dict(entry or {})
    entry_copy["deleted_at"] = datetime.utcnow().isoformat() + "Z"
    trash["users"][uid] = entry_copy
    save_trash(trash)

def restore_user_from_trash(uid: str):
    trash = load_trash()
    reg = load_registry()
    users = reg.get("users", {})
    tusers = trash.get("users", {})
    if uid not in tusers:
        return False, "Não está na lixeira."
    if uid in users:
        return False, "Já existe um usuário ativo com esse id."
    users[uid] = tusers[uid]
    users[uid].pop("deleted_at", None)
    reg["users"] = users
    save_registry(reg)
    del tusers[uid]
    trash["users"] = tusers
    save_trash(trash)
    return True, "Restaurado."

def empty_trash():
    save_trash({"users": {}})

# =============== Schulze (parcial + empates) ===============
def ballot_to_ranks(ballot):
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
                except Exception:
                    ranks[k] = None
        return ranks, peso
    ranking = ballot.get("ranking", [])
    r = 1
    ranks = {}
    for c in ranking:
        if c not in ranks:
            ranks[c] = r
            r += 1
    return ranks, peso

def compute_pairwise_weak(ballots, candidates):
    P = {a: {b: 0 for b in candidates if b != a} for a in candidates}
    for ballot in ballots:
        ranks, w = ballot_to_ranks(ballot)
        for a in candidates:
            ra = ranks.get(a, None)
            for b in candidates:
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
    return P

def schulze_strengths(P, candidates):
    S = {a: {b: 0 for b in candidates} for a in candidates}
    for a in candidates:
        for b in candidates:
            if a == b:
                continue
            S[a][b] = P[a][b] if P[a][b] > P[b][a] else 0
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
    P = compute_pairwise_weak(ballots, candidates)
    S = schulze_strengths(P, candidates)
    def score(x):
        wins   = sum(S[x][y] > S[y][x] for y in candidates if y != x)
        losses = sum(S[y][x] > S[x][y] for y in candidates if y != x)
        return (wins, -losses)
    ranking = sorted(candidates, key=score, reverse=True)
    return ranking, P, S

# =============== Helpers de chaves ===============
def _mk_key():
    alphabet = string.ascii_uppercase + string.digits
    part = lambda: "".join(secrets.choice(alphabet) for _ in range(4))
    return f"{part()}-{part()}-{part()}"

def _assigned_keys_set():
    reg = load_registry()
    out = set()
    for uid, entry in reg.get("users", {}).items():
        k = (entry or {}).get("key")
        if k:
            out.add(k)
    return out

def _free_keys_from_pool():
    keys = load_keys()["keys"]
    assigned = _assigned_keys_set()
    return [k for k, info in keys.items() if not info.get("used") and k not in assigned]

# =============== Rotas Públicas ===============

@app.route("/")
def index():
    return render_template("index.html", get_current_election_id=get_current_election_id)

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
    """
    Retorna lista de eleições com metadados (inclui category).
    Filtros opcionais: ?category=...&start=YYYY-MM-DD&end=YYYY-MM-DD
    Compat: ?flat=1 -> retorna apenas lista de eids (sem metadados)
    """
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

    # Ordena por data desc (eids sem data ficam no fim)
    enriched.sort(key=lambda x: x.get("date", ""), reverse=True)
    return Response(json.dumps({"elections": enriched}, ensure_ascii=False, indent=2), mimetype="application/json")

@app.route("/public/elections.csv")
def public_elections_csv():
    """
    Exporta lista (com filtros: ?category=&start=&end=) para CSV.
    Colunas: eid,title,date,time,tz,category
    """
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
        header = "candidate," + ",".join(candidates)
        return Response(header + "\n", mimetype="text/csv")
    ranking, pairwise, strength = schulze_ranking_from_ballots(ballots, candidates)
    csv_text = make_csv_pairwise(pairwise, candidates)
    resp = Response(csv_text, mimetype="text/csv")
    resp.headers["Content-Disposition"] = f'attachment; filename="pairwise_{eid}.csv"'
    return resp

# =============== Pacote de Auditoria (ZIP) ===============
def _sha256_file(path: Path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

@app.route("/admin/export_audit_bundle")
def admin_export_audit_bundle():
    if not require_admin(request):
        abort(403)
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
            manifest["files"].append({
                "arcname": arcname,
                "error": f"{e}"
            })

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for arcname, p in paths:
            z.write(p, arcname)
        readme = (
            "SchulzeVote - Pacote de Auditoria\n"
            f"EID: {eid}\n"
            "Conteúdo:\n"
            "- ballots/<eid>.json: cédulas (anônimas) desta votação\n"
            "- audit/<eid>.log: log de auditoria textual\n"
            "- config/candidates.json: lista de candidatos\n"
            "- config/election.json: EID atual, metadados (inclui categoria) e prazos\n"
            "- config/voter_keys.json: pool de chaves e status de uso\n"
            "- config/user_registry.json: cadastro (hash de senha, peso, tentativas)\n"
            "- config/user_trash.json: lixeira (soft delete)\n"
            "\n"
            "Integridade: ver MANIFEST.json (hashes SHA-256 de cada arquivo)\n"
            "Recomendado: guardar também o commit/hash do código (ex.: app.py) no fechamento da votação.\n"
        )
        z.writestr("README.txt", readme)
        z.writestr("MANIFEST.json", json.dumps(manifest, ensure_ascii=False, indent=2))
    buf.seek(0)
    resp = Response(buf.getvalue(), mimetype="application/zip")
    resp.headers["Content-Disposition"] = f'attachment; filename="audit_bundle_{eid}.zip"'
    return resp

# =============== Admin: Candidatos & Prazo (inline via render_template_string) ===============
@app.route("/admin/candidates", methods=["GET","POST"])
def admin_candidates():
    if not require_admin(request):
        abort(403)
    msg = warn = None
    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "save_candidates":
            raw = request.form.get("lista", "")
            lines = [_squash_spaces(ln) for ln in raw.splitlines()]
            save_candidates(lines)
            msg = "Candidatos salvos."
            audit_admin(
                get_current_election_id(),
                "SAVE_CAND",
                f"count={len([l for l in lines if l])}",
                request.remote_addr or "-"
            )
        elif action == "set_deadline":
            date_s = (request.form.get("date") or "").strip()
            time_s = (request.form.get("time") or "").strip()
            tz_s   = (request.form.get("tz") or "America/Sao_Paulo").strip()
            if not date_s or not time_s:
                warn = "Informe data e hora."
            else:
                try:
                    local_tz = ZoneInfo(tz_s)
                    y, m, d = [int(x) for x in date_s.split("-")]
                    hh, mm  = [int(x) for x in time_s.split(":")]
                    local_dt = datetime(y, m, d, hh, mm, tzinfo=local_tz)
                    save_deadline(local_dt.astimezone(timezone.utc))
                    msg = "Prazo definido."
                    audit_admin(
                        get_current_election_id(),
                        "SET_DEADLINE",
                        f"{date_s} {time_s} {tz_s}",
                        request.remote_addr or "-"
                    )
                except Exception as e:
                    warn = f"Erro: {e}"
        elif action == "clear_deadline":
            save_deadline(None)
            msg = "Prazo removido."
            audit_admin(get_current_election_id(), "CLEAR_DEADLINE", "ok", request.remote_addr or "-")

    current = load_candidates()
    core = [c for c in current if c not in (RESERVED_BLANK, RESERVED_NULL)]
    dl_utc = load_deadline()
    tz_default = "America/Sao_Paulo"
    if dl_utc:
        local = dl_utc.astimezone(ZoneInfo(tz_default))
        deadline_html = "<p><b>Prazo atual:</b> %s %s</p>" % (local.strftime('%d/%m/%Y %H:%M'), tz_default)
    else:
        deadline_html = "<p><i>Nenhum prazo definido.</i></p>"

    tmpl = """
    <!doctype html>
    <html lang="pt-BR">
    <head>
      <meta charset="utf-8"><title>Admin · Candidatos & Prazo</title>
      <style>
        body{font-family:system-ui;padding:24px}
        textarea{width:100%;min-height:200px}
        .msg{color:green}
        .warn{color:#b45309}
      </style>
    </head>
    <body>
      <h1>Admin · Candidatos &amp; Prazo</h1>
      {% if msg %}<p class="msg">{{ msg }}</p>{% endif %}
      {% if warn %}<p class="warn">{{ warn }}</p>{% endif %}

      <form method="POST">
        <input type="hidden" name="action" value="save_candidates">
        <p><b>Candidatos</b> (um por linha;
          <i>{{ RESERVED_BLANK }}</i>/<i>{{ RESERVED_NULL }}</i> são fixos no fim):</p>
        <textarea name="lista">{{ core_text }}</textarea><br><br>
        <button>Salvar candidatos</button>
      </form>

      <hr>
      <h2>Prazo de votação</h2>
      {{ deadline_html|safe }}
      <form method="POST">
        <input type="hidden" name="action" value="set_deadline">
        <label>Data: <input type="date" name="date"></label>
        <label>Hora: <input type="time" name="time"></label>
        <label>Fuso:
          <select name="tz">
            <option>America/Sao_Paulo</option>
            <option>America/Bahia</option>
            <option>America/Fortaleza</option>
            <option>America/Recife</option>
            <option>America/Maceio</option>
            <option>America/Manaus</option>
            <option>America/Belem</option>
            <option>America/Boa_Vista</option>
            <option>America/Porto_Velho</option>
            <option>America/Cuiaba</option>
            <option>America/Campo_Grande</option>
            <option>America/Noronha</option>
            <option>UTC</option>
          </select>
        </label>
        <button>Definir prazo</button>
      </form>

      <form method="POST" style="margin-top:8px">
        <input type="hidden" name="action" value="clear_deadline">
        <button>Limpar prazo</button>
      </form>

      <p style="margin-top:16px">
        <a href="/admin/election_meta?secret={{ secret_qs|e }}">Metadados da votação</a>
      </p>
      <p><a href="/">Início</a></p>
    </body>
    </html>
    """
    return render_template_string(
        tmpl,
        msg=msg, warn=warn,
        RESERVED_BLANK=RESERVED_BLANK,
        RESERVED_NULL=RESERVED_NULL,
        core_text="\n".join(core),
        deadline_html=deadline_html,
        secret_qs=request.args.get("secret", "")
    )

# =============== Admin: Election Meta (template com categoria) ===============
@app.route("/admin/election_meta", methods=["GET","POST"])
def admin_election_meta():
    if not require_admin(request):
        abort(403)
    d = load_election_doc()
    msg = warn = None
    if request.method == "POST":
        eid   = (request.form.get("eid") or d.get("election_id","default")).strip()
        title = (request.form.get("title") or "").strip()
        date  = (request.form.get("date") or "").strip()
        time  = (request.form.get("time") or "").strip()
        tz    = (request.form.get("tz") or "America/Sao_Paulo").strip()
        category = (request.form.get("category") or "").strip()
        if not eid or not title or not date or not time:
            warn = "Preencha EID, título, data e hora."
        else:
            set_election_meta(eid, title, date, time, tz, category)
            d["election_id"] = eid
            save_election_doc(d)
            msg = "Metadados salvos."
            audit_admin(
                eid,
                "SAVE_META",
                f"title='{title}' date={date} time={time} tz={tz} category='{category}'",
                request.remote_addr or "-"
            )

    meta = get_election_meta(d.get("election_id"))
    tz_opts_list = [
        "America/Sao_Paulo","America/Bahia","America/Fortaleza","America/Recife","America/Maceio",
        "America/Manaus","America/Belem","America/Boa_Vista","America/Porto_Velho",
        "America/Cuiaba","America/Campo_Grande","America/Noronha","UTC"
    ]

    return render_template(
        "admin_election_meta.html",
        msg=msg, warn=warn,
        election_id=d.get("election_id","default"),
        meta=meta,
        tz_options=tz_opts_list,
        secret_qs=request.args.get('secret','')
    )

# =============== Admin: Backups ZIP (global e por EID) ===============
@app.route("/admin/backup_zip")
def admin_backup_zip():
    if not require_admin(request): abort(403)

    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    buf = io.BytesIO()

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        # Ajuda local
        def add_if_exists(path, arcname=None):
            if os.path.exists(path):
                z.write(path, arcname or path)

        # 1) JSONs “raiz”
        for fname in [CAND_FILE, ELECTION_FILE, VOTER_KEYS_FILE, REGISTRY_FILE, TRASH_FILE]:
            add_if_exists(fname, fname)

        # 2) Tudo de data/ (ballots e audit)
        base_dir = str(DATA_DIR)   # normalmente "data" ou "/var/data"
        base_prefix = "data"       # como fica dentro do ZIP
        if os.path.exists(base_dir):
            for root, _, files in os.walk(base_dir):
                for f in files:
                    full = os.path.join(root, f)
                    rel = os.path.relpath(full, start=base_dir)
                    arc = os.path.join(base_prefix, rel)
                    z.write(full, arc)

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

    ballots_file = ballots_path(eid)    # data/ballots/<eid>.json
    audit_file   = audit_path(eid)      # data/audit/<eid>.log
    meta = get_election_meta(eid) or {}
    context = {
        "eid": eid,
        "meta": meta,
        "candidates_snapshot": load_candidates(),
    }

    ballots_exists = ballots_file.exists()
    audit_exists   = audit_file.exists()

    if not ballots_exists and not audit_exists:
        return Response(
            json.dumps({"error": "nenhum arquivo encontrado para este EID"}, ensure_ascii=False),
            status=404, mimetype="application/json"
        )

    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        if ballots_exists:
            z.write(str(ballots_file), f"data/ballots/{eid}.json")
        if audit_exists:
            z.write(str(audit_file),   f"data/audit/{eid}.log")
        z.writestr(f"meta/election_meta_{eid}.json", json.dumps(context, ensure_ascii=False, indent=2))
        if os.path.exists(ELECTION_FILE):
            z.write(ELECTION_FILE, "election.json")

    buf.seek(0)
    resp = Response(buf.getvalue(), mimetype="application/zip")
    resp.headers["Content-Disposition"] = f'attachment; filename="schulzevote_eid_{eid}_{ts}.zip"'
    return resp

# =============== Admin: Dados crus para auditoria ===============
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

# =============== Debug local ===============
if __name__ == "__main__":
    # Em produção (Render), o servidor do container web já chama sua app.
    # Este bloco é útil apenas para rodar localmente: python app.py
    app.run(host="0.0.0.0", port=5000, debug=True)
