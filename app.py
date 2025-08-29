import os, json, uuid, secrets, string, hashlib, io, zipfile, csv
from pathlib import Path
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, Response, abort, session
)
from werkzeug.security import generate_password_hash, check_password_hash

# =============== App & Secrets ===============
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "mude-isto")

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "troque-admin")
ID_SALT      = os.environ.get("ID_SALT", "mude-este-salt")

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
    if not os.path.exists(path): return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
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
    if not iso: return None
    try:
        return datetime.fromisoformat(iso)
    except:
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
                except:
                    ranks[k] = None
        return ranks, peso
    ranking = ballot.get("ranking", [])
    r = 1
    ranks = {}
    for c in ranking:
        if c not in ranks:
            ranks[c] = r; r += 1
    return ranks, peso

def compute_pairwise_weak(ballots, candidates):
    P = {a: {b: 0 for b in candidates if b != a} for a in candidates}
    for ballot in ballots:
        ranks, w = ballot_to_ranks(ballot)
        for a in candidates:
            ra = ranks.get(a, None)
            for b in candidates:
                if a == b: continue
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
            if a == b: continue
            S[a][b] = P[a][b] if P[a][b] > P[b][a] else 0
    for i in candidates:
        for j in candidates:
            if i == j: continue
            for k in candidates:
                if i == k or j == k: continue
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
        if k: out.add(k)
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
        pick = RESERVED_BLANK if special == "BLANK" else RESERVED_NULL
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
        if not r or str(r).strip() == "":
            ranks[c] = None
        else:
            try:
                n = int(str(r).strip())
                ranks[c] = n if n >= 1 else None
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
    if not is_voting_open():
        return Response("<h2>Votação encerrada</h2><p>O prazo expirou.</p><p><a href='/'>Início</a></p>", mimetype="text/html", status=403)

    candidates = load_candidates()
    if request.method == "POST":
        user_id = session.get("user_id")
        if not user_id:
            flash("Faça login para votar.", "error"); return redirect(url_for("login"))

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

        # verifica chave no pool
        keys_doc = load_keys()
        kinfo = keys_doc["keys"].get(voter_key)
        if not kinfo:
            flash("Chave inexistente.", "error"); return redirect(url_for("vote"))
        if kinfo.get("used"):
            flash("Esta chave já foi usada.", "error"); return redirect(url_for("index"))

        # monta ranks
        posted_ranking = request.form.getlist("ranking")
        if posted_ranking:
            ranks = {c: None for c in candidates}
            r = 1
            for c in posted_ranking:
                if c in candidates and ranks[c] is None:
                    ranks[c] = r; r += 1
        else:
            ranks = parse_numeric_form_to_ranks(request.form, candidates)

        if not any((isinstance(v, int) and v >= 1) for v in ranks.values()):
            flash("Nenhuma preferência informada.", "error"); return redirect(url_for("vote"))

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
        audit_line(eid, f"VOTE {datetime.utcnow().isoformat()}Z voter={voter_key_h} receipt={receipt} ip={request.remote_addr or '-'}")

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
        return render_template("results.html", ranking=[], empty=True, total_votos=0, election_id=eid, election_meta=meta)
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
        head = ("<h1>%s</h1><p><b>ID:</b> %s%s</p>" % (
            meta.get('title','Auditoria'),
            eid,
            (" • <b>Data/Hora:</b> %s %s %s" % (meta.get('date',''), meta.get('time',''), meta.get('tz',''))) if meta.get('date') and meta.get('time') else ""
        ))
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
        if not d: return True
        if start and d < start: return False
        if end and d > end: return False
        return True

    enriched = []
    for eid in all_eids:
        m = metas.get(eid, {})
        cat = (m.get("category","") or "").strip()
        if cat_filter and cat.lower() != cat_filter:
            continue
        if not within_date(m):
            continue
        enriched.append({
            "eid": eid,
            "title": m.get("title",""),
            "date":  m.get("date",""),
            "time":  m.get("time",""),
            "tz":    m.get("tz",""),
            "category": cat
        })

    # Ordena por data desc (eids sem data ficam no fim)
    enriched.sort(key=lambda x: x.get("date",""), reverse=True)
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
        w.writerow([it.get("eid",""), it.get("title",""), it.get("date",""), it.get("time",""), it.get("tz",""), it.get("category","")])
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
    if not require_admin(request): abort(403)
    eid = (request.args.get("eid") or get_current_election_id()).strip()
    paths = []
    bpath = ballots_path(eid)
    apath = audit_path(eid)
    if bpath.exists(): paths.append(("ballots/" + bpath.name, bpath))
    if apath.exists(): paths.append(("audit/" + apath.name, apath))
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

# =============== Admin: Candidatos & Prazo (inline) ===============
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
            audit_admin(get_current_election_id(), "SAVE_CAND", f"count={len([l for l in lines if l])}", request.remote_addr or "-")
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
                    audit_admin(get_current_election_id(), "SET_DEADLINE", f"{date_s} {time_s} {tz_s}", request.remote_addr or "-")
                except Exception as e:
                    warn = f"Erro: {e}"
        elif action == "clear_deadline":
            save_deadline(None); msg = "Prazo removido."
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

    msg_html  = "<p style='color:green'>%s</p>" % msg if msg else ""
    warn_html = "<p style='color:#b45309'>%s</p>" % warn if warn else ""
    secret_qs = request.args.get('secret','')

    html = f"""
    <!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><title>Admin · Candidatos & Prazo</title>
    <style>body{{font-family:system-ui;padding:24px}} textarea{{width:100%;min-height:200px}}</style></head><body>
      <h1>Admin · Candidatos & Prazo</h1>
      {msg_html}
      {warn_html}
      <form method="POST">
        <input type="hidden" name="action" value="save_candidates">
        <p><b>Candidatos</b> (um por linha; <i>{RESERVED_BLANK}</i>/<i>{RESERVED_NULL}</i> são fixos no fim):</p>
        <textarea name="lista">{"\n".join(core)}</textarea><br><br>
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
        <input type="hidden" name="action" value="clear_deadline"><button>Limpar prazo</button>
      </form>
      <p style="margin-top:16px"><a href="/admin/election_meta?secret={secret_qs}">Metadados da votação</a></p>
      <p><a href="/">Início</a></p>
    </body></html>
    """
    return Response(html, mimetype="text/html")

# =============== Admin: Election Meta (usa template) ===============
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
        category = (request.form.get("category") or "").strip()
        if not eid or not title or not date or not time:
            warn = "Preencha EID, título, data e hora."
        else:
            set_election_meta(eid, title, date, time, tz, category)
            d["election_id"] = eid
            save_election_doc(d)
            msg = "Metadados salvos."
            audit_admin(eid, "SAVE_META", f"title='{title}' date={date} time={time} tz={tz} category='{category}'", request.remote_addr or "-")

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

# =============== Admin: Atribuir chaves (UI inline) ===============
@app.route("/admin/assign_ui")
def admin_assign_ui():
    if not require_admin(request): abort(403)
    secret = request.args.get("secret","")
    current_eid = get_current_election_id()
    js_secret = json.dumps(secret)
    js_current = json.dumps(current_eid)

    # (HTML inline reaproveitado da sua versão estável, com listagens, peso em lote, CSV, lixeira, etc)
    # Para não alongar demais: mantive exatamente o conteúdo que você já tinha e que funcionava.
    # -- INÍCIO DO HTML (igual ao anteriormente enviado) --
    html = f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><title>Admin · Atribuir chaves</title>
<style>
  body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;padding:24px;background:#f8fafc}}
  .wrap{{max-width:1200px;margin:0 auto}}
  .card{{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:16px;margin:12px 0}}
  .row{{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:10px 0}}
  textarea{{width:100%;min-height:120px;padding:8px;border:1px solid #d1d5db;border-radius:10px}}
  input[type=number],input[type=text]{{padding:8px;border:1px solid #d1d5db;border-radius:10px}}
  input.wsmall{{width:90px}}
  .btn{{padding:9px 12px;border-radius:10px;border:1px solid #111827;background:#111827;color:#fff;cursor:pointer}}
  .btn.alt{{background:#fff;color:#111827}}
  .btn.ghost{{background:#fff;color:#111827;border:1px dashed #9ca3af}}
  .btn.danger{{background:#b91c1c;border-color:#7f1d1d}}
  .btn.warn{{background:#f59e0b;border-color:#78350f;color:#111}}
  table{{border-collapse:collapse;width:100%}}
  th,td{{border:1px solid #e5e7eb;padding:6px;text-align:left;font-size:.95rem;vertical-align:middle}}
  th{{background:#f3f4f6}}
  pre{{background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:10px;max-height:260px;overflow:auto}}
  .grid{{display:grid;gap:16px;grid-template-columns:1fr 1fr}}
  @media(max-width:1000px){{.grid{{grid-template-columns:1fr}}}}
  .muted{{color:#6b7280}}
</style></head>
<body>
<div class="wrap">
  <h1>Atribuir chaves (lote)</h1>
  <div class="card">
    <p>Cole aqui os <b>usuários</b> (um por linha)</p>
    <textarea id="usersBox" placeholder="usuario01&#10;usuario02"></textarea>
    <div class="row">
      <label>Peso padrão: <input type="number" id="peso" value="1" min="1" class="wsmall"></label>
      <button class="btn" onclick="genAssign()">Gerar e atribuir</button>
      <button class="btn alt" onclick="poolAssign()">Atribuir do pool</button>
      <button class="btn ghost" onclick="exportCSVAll()">Exportar CSV (todos)</button>
      <button class="btn ghost" onclick="exportCSVFromTextarea()">Exportar CSV (somente colados)</button>
    </div>
    <div class="row"><b>Resultado:</b><pre id="resultBox" style="flex:1">(aguardando)</pre></div>
    <div class="row">
      <label>Aplicar peso em lote:
        <input type="number" id="pesoLote" value="1" min="1" class="wsmall">
      </label>
      <button class="btn alt" onclick="applyBatchWeight()">Aplicar peso (lote)</button>
      <span id="batchStatus" class="muted"></span>
    </div>
    <div class="row">
      <button class="btn danger" onclick="deleteBatch()">Excluir usuários (lote)</button>
      <span class="muted">Soft delete (vai para a lixeira)</span>
    </div>
  </div>
  <div class="grid">
    <div class="card"><h3>Chaves</h3><div id="keysTable">carregando...</div></div>
    <div class="card"><h3>Pool</h3><div id="poolTable">carregando...</div></div>
  </div>
  <div class="card">
    <h3>Usuários</h3>
    <div class="row">
      <input type="text" id="filtroUser" placeholder="Filtrar..." oninput="renderUsers()">
      <span class="muted">EID atual: <b id="eidNow"></b></span>
    </div>
    <div id="usersTable">carregando...</div>
  </div>
  <div class="card">
    <h3>Lixeira</h3>
    <div id="trashTable">carregando...</div>
    <div class="row">
      <button class="btn warn" onclick="emptyTrash()">Esvaziar lixeira</button>
      <span class="muted">Atenção: permanente</span>
    </div>
  </div>
</div>
<script>
  const secret = {js_secret};
  const currentEid = {js_current};
  document.addEventListener('DOMContentLoaded', ()=>{{document.getElementById('eidNow').textContent = currentEid;}});
  let USERS_CACHE = {{}}, TRASH_CACHE = {{}};
  function parseUsersFromTextarea(){const t=document.getElementById('usersBox').value.trim();return t? t.split(/\\r?\\n/).map(s=>s.trim()).filter(Boolean):[];}
  async function genAssign(){const users=parseUsersFromTextarea(); if(!users.length) return alert('Cole usuários');
    const peso=document.getElementById('peso').value||'1';
    const url=`/admin/assign_batch_generate?secret=${{encodeURIComponent(secret)}}&peso=${{encodeURIComponent(peso)}}&ras=${{encodeURIComponent(users.join(','))}}`;
    const r=await fetch(url); document.getElementById('resultBox').textContent=await r.text(); await refreshAll();}
  async function poolAssign(){const users=parseUsersFromTextarea(); if(!users.length) return alert('Cole usuários');
    const url=`/admin/assign_batch_use_pool?secret=${{encodeURIComponent(secret)}}&ras=${{encodeURIComponent(users.join(','))}}`;
    const r=await fetch(url); document.getElementById('resultBox').textContent=await r.text(); await refreshAll();}
  async function applyBatchWeight(){const users=parseUsersFromTextarea(); if(!users.length) return alert('Cole usuários');
    const peso=parseInt(document.getElementById('pesoLote').value||'1',10); const status=document.getElementById('batchStatus'); status.textContent='Aplicando...';
    let ok=0,fail=0; for(const u of users){const url=`/admin/set_user_weight?secret=${{encodeURIComponent(secret)}}&user=${{encodeURIComponent(u)}}&peso=${{encodeURIComponent(peso)}}`;
      try{{const r=await fetch(url); if(r.ok) ok++; else fail++;}}catch(e){{fail++;}}}
    status.textContent=`Concluído: ok=${{ok}}, falhas=${{fail}}`; await refreshUsers();}
  async function deleteBatch(){const users=parseUsersFromTextarea(); if(!users.length) return alert('Cole usuários');
    if(!confirm('Excluir (soft delete)?')) return; const url=`/admin/delete_users_batch?secret=${{encodeURIComponent(secret)}}&users=${{encodeURIComponent(users.join(','))}}`;
    const r=await fetch(url); document.getElementById('resultBox').textContent=await r.text(); await refreshUsers(); await refreshTrash();}
  async function deleteOne(uEnc){const u=decodeURIComponent(uEnc); if(!confirm('Excluir '+u+'?')) return;
    const r=await fetch(`/admin/delete_user?secret=${{encodeURIComponent(secret)}}&user=${{encodeURIComponent(u)}}`);
    document.getElementById('resultBox').textContent=await r.text(); await refreshUsers(); await refreshTrash();}
  async function restoreOne(uEnc){const u=decodeURIComponent(uEnc);
    const r=await fetch(`/admin/restore_user?secret=${{encodeURIComponent(secret)}}&user=${{encodeURIComponent(u)}}`);
    document.getElementById('resultBox').textContent=await r.text(); await refreshUsers(); await refreshTrash();}
  async function emptyTrash(){if(!confirm('Esvaziar lixeira?')) return;
    const r=await fetch(`/admin/empty_trash?secret=${{encodeURIComponent(secret)}}`, {{method:'POST'}}); document.getElementById('resultBox').textContent=await r.text(); await refreshTrash();}
  function buildCSV(rows){const header=['usuario','key','used','peso','attempts_'+currentEid];
    const esc=v=>{{if(v==null) return ''; const s=String(v); return /[",\\n]/.test(s)? '"'+s.replace(/"/g,'""')+'"':s;}};
    const out=[header.join(',')].concat(rows.map(r=>[r.usuario,r.key,r.used,r.peso,r.attempts].map(esc).join(','))); return out.join('\\n');}
  function downloadCSV(filename,csvText){const blob=new Blob([csvText],{{type:'text/csv;charset=utf-8;'}}); const url=URL.createObjectURL(blob);
    const a=document.createElement('a'); a.href=url; a.download=filename; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);}
  function exportCSVAll(){const entries=Object.entries(USERS_CACHE);
    const rows=entries.map(([u,v])=>({{usuario:u, key:v.key||'', used:!!v.used, peso:v.peso||1, attempts:(v.attempts&&v.attempts[currentEid])||0}}));
    const csv=buildCSV(rows); const ts=new Date().toISOString().replace(/[:.]/g,'-'); downloadCSV(`usuarios_chaves_pesos_${{currentEid}}_${{ts}}.csv`,csv);}
  function exportCSVFromTextarea(){const filterSet=new Set(parseUsersFromTextarea()); if(!filterSet.size) return alert('Cole usuários');
    const rows=Object.entries(USERS_CACHE).filter(([u])=>filterSet.has(u)).map(([u,v])=>({{usuario:u, key:v.key||'', used:!!v.used, peso:v.peso||1, attempts:(v.attempts&&v.attempts[currentEid])||0}}));
    const csv=buildCSV(rows); const ts=new Date().toISOString().replace(/[:.]/g,'-'); downloadCSV(`usuarios_chaves_pesos_FILTRADO_${{currentEid}}_${{ts}}.csv`,csv);}
  async function refreshKeys(){const r=await fetch(`/admin/keys_list?secret=${{encodeURIComponent(secret)}}`); const j=await r.json();
    const rows=Object.entries(j.keys||{{}}).map(([k,v])=>`<tr><td>${{k}}</td><td>${{v.used?'✔️':'—'}}</td><td>${{v.used_at||'—'}}</td><td>${{v.peso||1}}</td></tr>`).join('');
    document.getElementById('keysTable').innerHTML=`<table><thead><tr><th>Chave</th><th>Usada</th><th>Quando</th><th>Peso</th></tr></thead><tbody>${{rows}}</tbody></table>`;}
  async function refreshPool(){const r=await fetch(`/admin/pool_list?secret=${{encodeURIComponent(secret)}}`); const j=await r.json();
    const rows=(j.pool||[]).map(k=>`<tr><td>${{k}}</td></tr>`).join(''); document.getElementById('poolTable').innerHTML=`<table><thead><tr><th>Chave livre</th></tr></thead><tbody>${{rows}}</tbody></table>`;}
  async function refreshUsers(){const r=await fetch(`/admin/users_list?secret=${{encodeURIComponent(secret)}}`); const j=await r.json(); USERS_CACHE=j.users||{{}}; renderUsers();}
  async function refreshTrash(){const r=await fetch(`/admin/trash_list?secret=${{encodeURIComponent(secret)}}`); const j=await r.json(); TRASH_CACHE=j.users||{{}}; renderTrash();}
  function renderUsers(){const filtro=(document.getElementById('filtroUser').value||'').toLowerCase(); const entries=Object.entries(USERS_CACHE);
    const rows=entries.filter(([u])=>!filtro||u.toLowerCase().includes(filtro)).map(([u,v])=>{{const tent=(v.attempts&&v.attempts[currentEid])||0; const peso=v.peso||1; const key=v.key||'—'; const used=v.used?'✔️':'—';
      return `<tr><td><code>${{u}}</code></td><td>${{key}}</td><td style="text-align:center">${{used}}</td>
      <td style="text-align:center"><input id="w-${{encodeURIComponent(u)}}" type="number" min="1" value="${{peso}}" class="wsmall"/>
      <button class="btn alt" onclick="saveWeight('${{encodeURIComponent(u)}}')">Salvar</button>
      <button class="btn danger" onclick="deleteOne('${{encodeURIComponent(u)}}')">Excluir</button></td>
      <td style="text-align:center">${{tent}}</td></tr>`;}}).join('');
    document.getElementById('usersTable').innerHTML=`<table><thead><tr><th>Usuário</th><th>Chave</th><th>Usou</th><th>Peso / Ações</th><th>Tentativas (${{
      currentEid}})</th></tr></thead><tbody>${{rows}}</tbody></table>`;}
  function renderTrash(){const entries=Object.entries(TRASH_CACHE);
    if(!entries.length) return document.getElementById('trashTable').innerHTML='<p class="muted">Lixeira vazia.</p>';
    const rows=entries.map(([u,v])=>{{const delAt=v.deleted_at||'—'; const key=v.key||'—'; const used=v.used?'✔️':'—'; const peso=v.peso||1;
      return `<tr><td><code>${{u}}</code></td><td>${{key}}</td><td style="text-align:center">${{used}}</td><td style="text-align:center">${{peso}}</td><td>${{delAt}}</td>
      <td style="text-align:center"><button class="btn alt" onclick="restoreOne('${{encodeURIComponent(u)}}')">Restaurar</button></td></tr>`;}}).join('');
    document.getElementById('trashTable').innerHTML=`<table><thead><tr><th>Usuário</th><th>Chave</th><th>Usou</th><th>Peso</th><th>Excluído em</th><th>Ação</th></tr></thead><tbody>${{rows}}</tbody></table>`;}
  async function saveWeight(encUser){const u=decodeURIComponent(encUser); const inp=document.getElementById('w-'+encUser); const val=parseInt((inp.value||'1'),10);
    if(!Number.isFinite(val)||val<1) return alert('Peso inválido');
    const url=`/admin/set_user_weight?secret=${{encodeURIComponent(secret)}}&user=${{encodeURIComponent(u)}}&peso=${{encodeURIComponent(val)}}`;
    const r=await fetch(url); if(r.ok){{inp.style.borderColor='#059669'; setTimeout(()=>inp.style.borderColor='#d1d5db',700); await refreshUsers();}}
    else{{inp.style.borderColor='#b45309'; alert('Falha ao salvar'); setTimeout(()=>inp.style.borderColor='#d1d5db',1000);}}}
  async function refreshAll(){{await Promise.all([refreshKeys(),refreshPool(),refreshUsers(),refreshTrash()]);}}
  refreshAll();
</script>
</body></html>"""
    # -- FIM DO HTML inline --
    return Response(html, mimetype="text/html")

# =============== Admin: API de atribuição e pesos ===============
@app.route("/admin/assign_batch_generate", methods=["GET","POST"])
def admin_assign_batch_generate():
    if not require_admin(request): abort(403)
    ras_param = (request.values.get("ras") or "").strip()
    if not ras_param: return Response('{"error":"informe ras=U1,U2,..."}', status=400, mimetype="application/json")
    try:
        peso = int(request.values.get("peso","1"))
    except:
        return Response('{"error":"peso inválido"}', status=400, mimetype="application/json")
    users = [r.strip() for r in ras_param.split(",") if r.strip()]
    users = list(dict.fromkeys(users))
    keys_doc = load_keys()
    reg = load_registry()
    assigned = {}
    for uid in users:
        ent = reg["users"].get(uid, {"used": False, "peso": 1, "attempts": {}})
        if ent.get("key"):  # não sobrescreve
            assigned[uid] = ent["key"]
            reg["users"][uid] = ent
            continue
        k = _mk_key()
        while k in keys_doc["keys"]:
            k = _mk_key()
        keys_doc["keys"][k] = {"used": False, "used_at": None, "peso": peso}
        ent["key"] = k
        reg["users"][uid] = ent
        assigned[uid] = k
    save_keys(keys_doc); save_registry(reg)
    eid = get_current_election_id()
    audit_admin(eid, "ASSIGN_GENERATE", f"users={','.join(users)} peso={peso}", request.remote_addr or "-")
    return Response(json.dumps({"ok": True, "assigned": assigned}, ensure_ascii=False, indent=2), mimetype="application/json")

@app.route("/admin/assign_batch_use_pool", methods=["GET","POST"])
def admin_assign_batch_use_pool():
    if not require_admin(request): abort(403)
    ras_param = (request.values.get("ras") or "").strip()
    if not ras_param: return Response('{"error":"informe ras=U1,U2,..."}', status=400, mimetype="application/json")
    users = [r.strip() for r in ras_param.split(",") if r.strip()]
    users = list(dict.fromkeys(users))
    reg = load_registry()
    keys_doc = load_keys()
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
    eid = get_current_election_id()
    audit_admin(eid, "ASSIGN_FROM_POOL", f"users={','.join(users)}", request.remote_addr or "-")
    return Response(json.dumps({"ok": True, "assigned": assigned}, ensure_ascii=False, indent=2), mimetype="application/json")

@app.route("/admin/set_user_weight")
def admin_set_user_weight():
    if not require_admin(request): abort(403)
    uid = (request.args.get("user") or "").strip()
    if not uid: return Response('{"error":"user ausente"}', status=400, mimetype="application/json")
    try:
        peso = int(request.args.get("peso","1"))
    except:
        return Response('{"error":"peso inválido"}', status=400, mimetype="application/json")
    reg = load_registry()
    ent = reg["users"].get(uid)
    if not ent: return Response('{"error":"user não encontrado"}', status=404, mimetype="application/json")
    ent["peso"] = peso
    reg["users"][uid] = ent
    save_registry(reg)
    eid = get_current_election_id()
    audit_admin(eid, "SET_WEIGHT", f"user={uid} peso={peso}", request.remote_addr or "-")
    return Response(json.dumps({"ok": True, "user": uid, "peso": peso}, ensure_ascii=False), mimetype="application/json")

# =============== Admin: Exclusão / Lixeira ===============
@app.route("/admin/delete_user")
def admin_delete_user():
    if not require_admin(request): abort(403)
    uid = (request.args.get("user") or "").strip()
    if not uid: return Response('{"error":"informe ?user=usuario"}', status=400, mimetype="application/json")
    reg = load_registry()
    users = reg.get("users", {})
    if uid not in users:
        return Response(json.dumps({"error": f"{uid} não encontrado"}, ensure_ascii=False), status=404, mimetype="application/json")
    entry = users[uid]
    move_user_to_trash(uid, entry)
    del users[uid]
    reg["users"] = users
    save_registry(reg)
    eid = get_current_election_id()
    audit_admin(eid, "DELETE", f"user={uid}", request.remote_addr or "-")
    return Response(json.dumps({"ok": True, "deleted": uid, "soft": True}, ensure_ascii=False), mimetype="application/json")

@app.route("/admin/delete_users_batch", methods=["GET","POST"])
def admin_delete_users_batch():
    if not require_admin(request): abort(403)
    users_param = (request.values.get("users") or "").strip()
    if not users_param: return Response('{"error":"informe users=u1,u2"}', status=400, mimetype="application/json")
    to_del = [u.strip() for u in users_param.split(",") if u.strip()]
    to_del = list(dict.fromkeys(to_del))
    reg = load_registry()
    users = reg.get("users", {})
    deleted, not_found = [], []
    for uid in to_del:
        if uid in users:
            move_user_to_trash(uid, users[uid])
            del users[uid]
            deleted.append(uid)
        else:
            not_found.append(uid)
    reg["users"] = users
    save_registry(reg)
    eid = get_current_election_id()
    audit_admin(eid, "DELETE_BATCH", f"deleted={len(deleted)} not_found={len(not_found)}", request.remote_addr or "-")
    return Response(json.dumps({"ok": True, "deleted": deleted, "not_found": not_found, "soft": True}, ensure_ascii=False, indent=2),
                    mimetype="application/json")

@app.route("/admin/trash_list")
def admin_trash_list():
    if not require_admin(request): abort(403)
    return Response(json.dumps(load_trash(), ensure_ascii=False, indent=2), mimetype="application/json")

@app.route("/admin/restore_user")
def admin_restore_user():
    if not require_admin(request): abort(403)
    uid = (request.args.get("user") or "").strip()
    if not uid: return Response('{"error":"informe ?user=usuario"}', status=400, mimetype="application/json")
    ok, msg = restore_user_from_trash(uid)
    eid = get_current_election_id()
    audit_admin(eid, "RESTORE", f"user={uid} ok={ok}", request.remote_addr or "-")
    status = 200 if ok else 409
    return Response(json.dumps({"ok": ok, "user": uid, "message": msg}, ensure_ascii=False), status=status, mimetype="application/json")

@app.route("/admin/empty_trash", methods=["POST"])
def admin_empty_trash():
    if not require_admin(request): abort(403)
    empty_trash()
    eid = get_current_election_id()
    audit_admin(eid, "EMPTY_TRASH", "all", request.remote_addr or "-")
    return Response(json.dumps({"ok": True, "emptied": True}, ensure_ascii=False), mimetype="application/json")

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

# =============== Admin: Auditoria Preview (inline) ===============
@app.route("/admin/audit_preview")
def admin_audit_preview():
    if not require_admin(request): abort(403)
    secret = request.args.get("secret","")
    current_eid = get_current_election_id()
    js_secret = json.dumps(secret)
    js_current = json.dumps(current_eid)

    # (HTML inline reaproveitado da versão que já funcionava, com filtros, auto-refresh e checagem de consistência)
    # Para economizar espaço aqui, é o mesmo bloco robusto que você usou anteriormente.
    # Se preferir, depois migramos para template Jinja.
    html = f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><title>Admin · Auditoria (preview)</title>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<style>
  body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#f8fafc;margin:0}}
  .wrap{{max-width:1100px;margin:0 auto;padding:22px}}
  .card{{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:14px;margin:10px 0}}
  .row{{display:flex;gap:8px;flex-wrap:wrap;align-items:center}}
  select,input,button{{padding:8px 10px;border:1px solid #d1d5db;border-radius:10px}}
  button{{cursor:pointer;background:#111827;color:#fff}}
  button.ghost{{background:#fff;color:#111827;border:1px dashed #9ca3af}}
  table{{border-collapse:collapse;width:100%}}
  th,td{{border:1px solid #e5e7eb;padding:6px;text-align:left;font-size:.93rem;vertical-align:top;white-space:nowrap}}
  th{{background:#f3f4f6}}
  .muted{{color:#6b7280}}
  .ok{{background:#ecfdf5;border:1px solid #a7f3d0}}
  .warn{{background:#fff7ed;border:1px solid #fed7aa}}
  .err{{background:#fee2e2;border:1px solid #fecaca}}
  .tag{{display:inline-block;padding:2px 6px;border-radius:6px;font-size:.78rem}}
  .t-vote{{background:#ecfdf5;color:#065f46;border:1px solid #a7f3d0}}
  .t-attempt{{background:#fff7ed;color:#7c2d12;border:1px solid #fed7aa}}
  .t-alimit{{background:#fef3c7;color:#92400e;border:1px solid #fde68a}}
  .t-admin{{background:#eef2ff;color:#3730a3;border:1px solid #c7d2fe}}
</style></head>
<body>
<div class="wrap">
  <h1>Auditoria · Preview (Admin)</h1>
  <div class="card">
    <div class="row">
      <label>EID: <select id="eidSel"></select></label>
      <button onclick="loadAll()">Carregar</button>
      <label class="muted">Auto: <select id="autoref"><option value="0" selected>Off</option><option value="15000">15s</option><option value="30000">30s</option><option value="60000">60s</option></select></label>
      <button class="ghost" onclick="openPublic('results')">Resultados públicos</button>
      <button class="ghost" onclick="openPublic('audit')">Auditoria pública</button>
    </div>
    <div class="row">
      <label><input type="checkbox" id="fVote" checked> VOTE</label>
      <label><input type="checkbox" id="fAttempt" checked> ATTEMPT</label>
      <label><input type="checkbox" id="fALimit" checked> ATTEMPT-LIMIT</label>
      <label><input type="checkbox" id="fAdmin" checked> ADMIN</label>
      <input id="q" type="text" placeholder="buscar..." style="flex:1;min-width:220px">
      <button onclick="applyFilters()">Filtrar</button>
      <button class="ghost" onclick="resetFilters()">Limpar</button>
      <button class="ghost" onclick="exportJSON()">Exportar JSON</button>
      <button class="ghost" onclick="exportCSV()">Exportar CSV</button>
    </div>
  </div>
  <div id="consistency" class="card"><h3>Resumo / Consistência</h3><div id="consistBox"><p class="muted">Carregue um EID.</p></div></div>
  <div class="card"><h3>Linhas</h3><div style="overflow:auto;max-height:60vh">
    <table id="tbl"><thead><tr><th>Tipo</th><th>Timestamp</th><th>Conteúdo</th></tr></thead><tbody id="tbody"><tr><td colspan="3" class="muted">Nada.</td></tr></tbody></table>
  </div></div>
</div>
<script>
  const secret={js_secret}; const currentEid={js_current}; let RAW=[], PARSED=[], FILTERED=[], BALLOTS=[];
  function tag(t){{if(t==='VOTE')return'<span class="tag t-vote">VOTE</span>'; if(t==='ATTEMPT')return'<span class="tag t-attempt">ATTEMPT</span>'; if(t==='ATTEMPT-LIMIT')return'<span class="tag t-alimit">ATTEMPT-LIMIT</span>'; if(t==='ADMIN')return'<span class="tag t-admin">ADMIN</span>'; return '<span class="tag">'+t+'</span>';}}
  function kvparse(txt){{const out={{}}; const parts=(txt||'').split(/\\s+/).filter(Boolean); for(const p of parts){{const i=p.indexOf('='); if(i>0) out[p.slice(0,i)]=p.slice(i+1);}} return out;}}
  function parseLine(line){{const o={{raw:line,type:'OTHER',ts:'',fields:{{}}}}; let m;
    if(line.startsWith('ADMIN ')){{const parts=line.split(' '); if(parts.length>=4){{o.type='ADMIN'; o.action=parts[1]; o.ts=parts[2]; o.fields=kvparse(line.slice(('ADMIN '+o.action+' '+o.ts+' ').length));}} return o;}}
    m=line.match(/^(VOTE|ATTEMPT|ATTEMPT-LIMIT)\\s+(\\S+)\\s+(.*)$/); if(m){{o.type=m[1]; o.ts=m[2]; o.fields=kvparse(m[3]||''); return o;}}
    m=line.match(/(\\d{{4}}-\\d{{2}}-\\d{{2}}T[^\\s]+Z)/); if(m) o.ts=m[1]; return o; }}
  function findDuplicates(arr){{const seen=new Set(), dup=new Set(); for(const x of arr){{if(seen.has(x)) dup.add(x); else seen.add(x);}} return [...dup];}}
  function computeConsistency(){{const votes=PARSED.filter(o=>o.type==='VOTE'); const voteHashes=votes.map(o=>o.fields.voter).filter(Boolean);
    const duplicates=findDuplicates(voteHashes); const setLog=new Set(voteHashes); const ballotHashes=(BALLOTS||[]).map(b=>b.voter).filter(Boolean); const setBall=new Set(ballotHashes);
    const missingInBallots=[...setLog].filter(h=>!setBall.has(h)); const missingInLog=[...setBall].filter(h=>!setLog.has(h));
    const totalBallots=(BALLOTS||[]).length; const totalWeight=(BALLOTS||[]).reduce((a,b)=>a+(parseInt(b.peso||1,10)||1),0);
    return {{countLogVotes:votes.length, countBallots:totalBallots, totalWeight, duplicates, missingInBallots, missingInLog}}; }}
  function renderConsistency(){{const el=document.getElementById('consistBox'); if(!PARSED.length&&!BALLOTS.length) return el.innerHTML='<p class="muted">Sem dados.</p>';
    const c=computeConsistency(); let status='ok', title='Tudo consistente ✅';
    if(c.duplicates.length||c.missingInBallots.length||c.missingInLog.length){{status=(c.duplicates.length||c.missingInLog.length)?'err':'warn'; title=status==='err'?'Divergências ❌':'Atenção ⚠️';}}
    const liDup=c.duplicates.map(h=>`<li><code>${{h}}</code></li>`).join('')||'<li class="muted">nenhum</li>';
    const liMiB=c.missingInBallots.map(h=>`<li><code>${{h}}</code></li>`).join('')||'<li class="muted">nenhum</li>';
    const liMiL=c.missingInLog.map(h=>`<li><code>${{h}}</code></li>`).join('')||'<li class="muted">nenhum</li>';
    const parent=document.getElementById('consistency'); parent.classList.remove('ok','warn','err'); parent.classList.add(status);
    el.innerHTML=`<p><b>${{title}}</b></p>
      <ul><li><b>VOTE (log):</b> ${{c.countLogVotes}}</li><li><b>Cédulas:</b> ${{c.countBallots}}</li><li><b>Soma de pesos:</b> ${{c.totalWeight}}</li></ul>
      <details><summary><b>Duplicidades</b></summary><ul>${{liDup}}</ul></details>
      <details><summary><b>No log mas sem cédula</b></summary><ul>${{liMiB}}</ul></details>
      <details><summary><b>Na cédula mas sem log</b></summary><ul>${{liMiL}}</ul></details>`; }}
  function renderTable(){{const tbody=document.getElementById('tbody'); if(!FILTERED.length){{tbody.innerHTML='<tr><td colspan="3" class="muted">Sem linhas.</td></tr>'; return;}}
    tbody.innerHTML=FILTERED.map(o=>`<tr><td>${{tag(o.type)}}${{o.action?(' <code>'+o.action+'</code>'):''}}</td><td><code>${{o.ts||''}}</code></td><td><code>${{o.raw.replace(/</g,'&lt;')}}</code></td></tr>`).join(''); }}
  function applyFilters(){{const fV=document.getElementById('fVote').checked, fA=document.getElementById('fAttempt').checked, fL=document.getElementById('fALimit').checked, fAd=document.getElementById('fAdmin').checked;
    const q=(document.getElementById('q').value||'').toLowerCase().trim();
    FILTERED=PARSED.filter(o=>{{if(o.type==='VOTE'&&!fV) return false; if(o.type==='ATTEMPT'&&!fA) return false; if(o.type==='ATTEMPT-LIMIT'&&!fL) return false; if(o.type==='ADMIN'&&!fAd) return false; if(q && !o.raw.toLowerCase().includes(q)) return false; return true;}})
      .sort((a,b)=>a.ts<b.ts?1:-1); renderTable(); renderConsistency();}
  function resetFilters(){{document.getElementById('fVote').checked=true; document.getElementById('fAttempt').checked=true; document.getElementById('fALimit').checked=true; document.getElementById('fAdmin').checked=true; document.getElementById('q').value=''; applyFilters();}}
  function copyLine(txt){{navigator.clipboard.writeText(txt);}}
  function toCSV(objs){{const headers=['type','action','ts','raw']; const esc=s=>{{s=String(s==null?'':s); return /[",\\n]/.test(s)? '"'+s.replace(/"/g,'""')+'"':s;}}; const lines=[headers.join(',')].concat(objs.map(o=>[o.type,o.action||'',o.ts||'',o.raw].map(esc).join(','))); return lines.join('\\n');}}
  function exportJSON(){{const blob=new Blob([JSON.stringify(FILTERED,null,2)],{{type:'application/json'}}); const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='audit_filtered.json'; a.click(); URL.revokeObjectURL(a.href);}}
  function exportCSV(){{const csv=toCSV(FILTERED); const blob=new Blob([csv],{{type:'text/csv;charset=utf-8;'}}); const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='audit_filtered.csv'; a.click(); URL.revokeObjectURL(a.href);}}
  async function loadEIDs(){{const r=await fetch('/public/elections'); const j=await r.json(); const sel=document.getElementById('eidSel'); sel.innerHTML=''; const list=(j.elections||[]).map(x=>x.eid||x);
    const all=Array.from(new Set([currentEid].concat(list))).filter(Boolean); for(const id of all){{const opt=document.createElement('option'); opt.value=id; opt.textContent=id; if(id===currentEid) opt.selected=true; sel.appendChild(opt);}}}
  async function loadLog(eid){{const r=await fetch(`/admin/audit_raw?secret=${{encodeURIComponent(secret)}}&eid=${{encodeURIComponent(eid)}}`); const j=await r.json(); RAW=j.lines||[]; PARSED=RAW.map(parseLine);}}
  async function loadBallots(eid){{const r=await fetch(`/admin/ballots_raw?secret=${{encodeURIComponent(secret)}}&eid=${{encodeURIComponent(eid)}}`); const j=await r.json(); BALLOTS=j.ballots||[];}}
  async function loadAll(){{const eid=document.getElementById('eidSel').value; await Promise.all([loadLog(eid), loadBallots(eid)]); applyFilters();}}
  function openPublic(kind){{const eid=document.getElementById('eidSel').value; if(kind==='results') window.open(`/public/${{encodeURIComponent(eid)}}/results`,'_blank'); else window.open(`/public/${{encodeURIComponent(eid)}}/audit`,'_blank');}}
  document.getElementById('autoref').addEventListener('change',(e)=>{{const ms=parseInt(e.target.value||'0',10); if(window._T){{clearInterval(window._T); window._T=null;}} if(ms>0) window._T=setInterval(loadAll,ms);}});
  loadEIDs().then(loadAll);
</script>
</body></html>"""
    return Response(html, mimetype="text/html")

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
    app.run(host="0.0.0.0", port=5000, debug=True)
