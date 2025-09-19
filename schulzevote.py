import os, json, uuid, secrets, string, hashlib, io, zipfile, csv
from pathlib import Path
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from typing import List, Dict, Tuple, Optional
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
# Expõe para os templates Jinja (usado no base_admin.html e base.html, se existirem)
app.jinja_env.globals['APP_VERSION'] = APP_VERSION

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "troque-admin")
ID_SALT      = os.environ.get("ID_SALT", "mude-este-salt")
app.config["ADMIN_SECRET"] = ADMIN_SECRET

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

# Candidatos especiais (sempre no fim da lista exibida)
RESERVED_BLANK = "Voto em Branco"
RESERVED_NULL  = "Voto Nulo"

# =============== Utils ===============
def norm(s: str) -> str:
    return (s or "").strip().upper()

def _squash_spaces(s: str) -> str:
    return " ".join((s or "").strip().split())

def key_hash(k: str) -> str:
    return hashlib.sha256((ID_SALT + norm(k)).encode()).hexdigest()

def require_admin(req) -> bool:
    """Autorização simples via querystring ?secret=... ou header X-Admin-Secret."""
    token = req.args.get("secret") or req.headers.get("X-Admin-Secret")
    return bool(ADMIN_SECRET and token == ADMIN_SECRET)

def _read_json(path: str | Path, default):
    path = str(path)
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def _write_json(path: str | Path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# =============== Persistência: candidatos / chaves / usuários / lixeira ===============
def _ensure_candidates_doc(lst: List[str]) -> List[str]:
    base = [_squash_spaces(x) for x in lst if _squash_spaces(x)]
    base = [x for x in base if x not in (RESERVED_BLANK, RESERVED_NULL)]
    base = list(dict.fromkeys(base))  # únicos preservando ordem
    base += [RESERVED_BLANK, RESERVED_NULL]
    return base

def load_candidates() -> List[str]:
    # Retorna lista com "Branco" e "Nulo" garantidos no fim
    raw = _read_json(CAND_FILE, [])
    return _ensure_candidates_doc(raw)

def save_candidates(lines: List[str]) -> None:
    # Salva apenas a lista "core" (sem Branco/Nulo); load_candidates reanexa
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

def _ensure_keys_doc() -> Dict:
    d = _read_json(VOTER_KEYS_FILE, {})
    d.setdefault("keys", {})   # "KEY": {"used":false,"used_at":null,"peso":1}
    d.setdefault("pool", [])   # lista de chaves livres (strings)
    return d

def load_keys() -> Dict:
    return _ensure_keys_doc()

def save_keys(doc: Dict) -> None:
    _write_json(VOTER_KEYS_FILE, doc)

def _ensure_registry() -> Dict:
    d = _read_json(REGISTRY_FILE, {})
    d.setdefault("users", {})  # "user": {"pwd_hash":..., "key": "...", "used":false, "peso":1, "attempts":{eid:n}}
    return d

def load_registry() -> Dict:
    return _ensure_registry()

def save_registry(reg: Dict) -> None:
    _write_json(REGISTRY_FILE, reg)

def load_trash() -> Dict:
    return _read_json(TRASH_FILE, {"users": {}})

def save_trash(t: Dict) -> None:
    _write_json(TRASH_FILE, t)

# =============== Election (id, prazo, meta) ===============
def load_election_doc() -> Dict:
    d = _read_json(ELECTION_FILE, {})
    d.setdefault("election_id", "default")
    d.setdefault("deadline_utc", None)
    d.setdefault("meta", {})  # meta[eid] = {title, date, time, tz, category, updated_at}
    return d

def save_election_doc(d: Dict) -> None:
    _write_json(ELECTION_FILE, d)

def get_current_election_id() -> str:
    return load_election_doc().get("election_id", "default")

def set_current_election_id(eid: str) -> None:
    d = load_election_doc()
    d["election_id"] = (eid or "default").strip() or "default"
    save_election_doc(d)

def set_election_meta(eid: str, title: str, date_s: str, time_s: str, tz_s: str, category: str = "") -> None:
    d = load_election_doc()
    d["meta"][eid] = {
        "title": (title or "").strip(),
        "date":  (date_s or "").strip(),
        "time":  (time_s or "").strip(),
        "tz":    (tz_s or "America/Sao_Paulo").strip(),
        "category": (category or "").strip(),
        "updated_at": datetime.utcnow().isoformat() + "Z"
    }
    save_election_doc(d)

def get_election_meta(eid: str) -> Optional[Dict]:
    return load_election_doc().get("meta", {}).get(eid, None)

def load_deadline() -> Optional[datetime]:
    iso = load_election_doc().get("deadline_utc")
    if not iso:
        return None
    try:
        # Esperamos string ISO como "YYYY-MM-DDTHH:MM:SS+00:00"
        return datetime.fromisoformat(iso)
    except Exception:
        return None

def save_deadline(dt_utc: Optional[datetime]) -> None:
    d = load_election_doc()
    d["deadline_utc"] = None if dt_utc is None else dt_utc.astimezone(timezone.utc).isoformat()
    save_election_doc(d)

def is_voting_open() -> bool:
    dl = load_deadline()
    if dl is None:
        return True
    return datetime.now(timezone.utc) < dl

# =============== Auditoria & Cédulas ===============
def ballots_path(eid: str) -> Path:
    return BAL_DIR / f"{eid}.json"

def audit_path(eid: str) -> Path:
    return AUDIT_DIR / f"{eid}.log"

def load_ballots(eid: str) -> List[dict]:
    return _read_json(str(ballots_path(eid)), [])

def save_ballots(eid: str, items: List[dict]) -> None:
    _write_json(str(ballots_path(eid)), items)

def append_ballot(eid: str, ballot_obj: dict) -> None:
    items = load_ballots(eid)
    items.append(ballot_obj)
    save_ballots(eid, items)

def audit_line(eid: str, text: str) -> None:
    p = audit_path(eid)
    with open(p, "a", encoding="utf-8") as f:
        f.write(text.rstrip() + "\n")

def audit_admin(eid: str, action: str, detail: str, ip: str = "-") -> None:
    ts = datetime.utcnow().isoformat() + "Z"
    audit_line(eid, f"ADMIN {action} {ts} {detail} by_ip={ip}")

# =============== Schulze (cálculo de ranking) ===============
def _pairwise_from_ballots(ballots: List[dict], candidates: List[str]) -> Dict[str, Dict[str, int]]:
    # Constrói matriz P[a][b] = número (peso) de votos que preferem a sobre b
    P = {a: {b: 0 for b in candidates if b != a} for a in candidates}
    for b in ballots:
        peso = int(b.get("peso", 1))
        ranks = b.get("ranks", {})
        for a in candidates:
            for c in candidates:
                if a == c:
                    continue
                ra = ranks.get(a, None)
                rc = ranks.get(c, None)
                if isinstance(ra, int) and isinstance(rc, int) and ra < rc:
                    P[a][c] += peso
    return P

def schulze_ranking_from_ballots(
    ballots: List[dict],
    candidates: List[str]
) -> Tuple[List[str], Dict[str, Dict[str, int]], Dict[str, Dict[str, int]]]:
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
            S[a][b] = P[a][b] if P[a][b] > P[b][a] else 0

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
    from functools import cmp_to_key

    def _cmp(a, b):
        if a == b:
            return 0
        if S[a][b] > S[b][a]:
            return -1
        if S[a][b] < S[b][a]:
            return 1
        # Empate: fallback lexicográfico estável
        al, bl = a.lower(), b.lower()
        if al < bl:
            return -1
        if al > bl:
            return 1
        return 0

    ranked_core = sorted(core_cands, key=cmp_to_key(_cmp))
    return ranked_core, P, S

# =============== Rotas Públicas (núcleo) ===============
@app.route("/")
def index():
    # Mantemos chamada ao template externo se existir; se não existir, exibe fallback leve
    try:
        return render_template("index.html", get_current_election_id=get_current_election_id)
    except Exception:
        eid = get_current_election_id()
        return render_template_string(
            "<h1>SchulzeVote</h1>"
            "<p>Votação atual: <b>{{ eid }}</b></p>"
            "<p><a href='{{ url_for(\"vote\") }}'>Votar</a> · "
            "<a href='{{ url_for(\"results_current\") }}'>Resultados</a></p>",
            eid=eid
        )

@app.route("/schulze_guide")
def schulze_guide():
    # Apenas renderiza o template; se ausente, fornece um fallback mínimo
    try:
        return render_template("schulze_guide.html")
    except Exception:
        return render_template_string(
            "<h1>Método de Schulze</h1>"
            "<p>Esta página explica o método de Schulze. "
            "Coloque um arquivo <code>templates/schulze_guide.html</code> para conteúdo completo.</p>"
        )

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
    try:
        return render_template("register.html")
    except Exception:
        # fallback ultra-simples
        return render_template_string(
            "<h1>Cadastro</h1>"
            "<form method='post'>"
            "Usuário: <input name='user_id'><br>"
            "Senha: <input name='password' type='password'><br>"
            "Repita a senha: <input name='password2' type='password'><br>"
            "<button>Cadastrar</button>"
            "</form>"
        )

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
    try:
        return render_template("login.html")
    except Exception:
        # fallback
        return render_template_string(
            "<h1>Login</h1>"
            "<form method='post'>"
            "Usuário: <input name='user_id'><br>"
            "Senha: <input name='password' type='password'><br>"
            "<button>Entrar</button>"
            "</form>"
        )

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("Você saiu.", "info")
    return redirect(url_for("index"))

# Helpers para leitura do formulário de voto
def parse_numeric_form_to_ranks(form, candidates: List[str]) -> Dict[str, Optional[int]]:
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

def _inc_attempt(user_id: str, eid: str) -> int:
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

        try:
            return render_template("receipt.html", receipt=receipt, eid=eid)
        except Exception:
            return render_template_string(
                "<h2>Voto computado</h2>"
                "<p>Recibo: <code>{{ receipt }}</code></p>"
                "<p><a href='{{ url_for(\"index\") }}'>Início</a></p>",
                receipt=receipt
            )

    # GET
    try:
        return render_template("vote.html", candidates=candidates)
    except Exception:
        # fallback simples
        items = "".join(f"<li>{c}</li>" for c in candidates)
        return render_template_string(
            "<h1>Voto</h1>"
            "<p>Esta é uma versão mínima de fallback. Para usar a interface completa,"
            " inclua o template <code>templates/vote.html</code>.</p>"
            f"<ul>{items}</ul>"
        )

# =============== Resultados & Auditoria pública ===============
@app.route("/results")
def results_current():
    return redirect(url_for("public_results", eid=get_current_election_id()))

@app.route("/public/<eid>/results")
def public_results(eid: str):
    ballots = load_ballots(eid)
    meta = get_election_meta(eid)
    if not ballots:
        try:
            return render_template(
                "results.html",
                ranking=[], empty=True, total_votos=0,
                election_id=eid, election_meta=meta
            )
        except Exception:
            return render_template_string(
                "<h2>Resultados</h2>"
                "<p>Nenhuma cédula encontrada para <b>{{ eid }}</b>.</p>",
                eid=eid
            )
    try:
        candidates = load_candidates()
        ranking, pairwise, strength = schulze_ranking_from_ballots(ballots, candidates)
        try:
            return render_template(
                "results.html",
                ranking=ranking, empty=False,
                total_votos=sum(int(b.get('peso', 1)) for b in ballots),
                election_id=eid, election_meta=meta,
                candidates=candidates if request.args.get("debug") == "1" else None,
                pairwise=pairwise if request.args.get("debug") == "1" else None,
                strength=strength if request.args.get("debug") == "1" else None
            )
        except Exception:
            # Fallback render
            lis = "".join(f"<li>{i+1}. {c}</li>" for i, c in enumerate(ranking))
            total = sum(int(b.get("peso", 1)) for b in ballots)
            return render_template_string(
                "<h2>Resultados (fallback)</h2>"
                "<p>Votação: <b>{{ eid }}</b></p>"
                "<p>Total de peso: <b>{{ total }}</b></p>"
                f"<ol>{lis}</ol>",
                eid=eid, total=total
            )
    except Exception as e:
        return Response(f"Erro ao calcular resultados: {e}", status=500)

@app.route("/public/<eid>/audit")
def public_audit(eid: str):
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

    def within_date(m: Dict) -> bool:
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
    # Reutiliza a mesma lógica de /public/elections
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
def make_csv_ranking(ranking: List[str], total_weight: int) -> str:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["posicao", "candidato"])
    for i, c in enumerate(ranking, start=1):
        w.writerow([i, c])
    w.writerow([])
    w.writerow(["total_peso", total_weight])
    return out.getvalue()

def make_csv_pairwise(P: Dict[str, Dict[str, int]], candidates: List[str]) -> str:
    out = io.StringIO()
    w = csv.writer(out)
    header = ["candidate"] + candidates
    w.writerow(header)
    for a in candidates:
        row = [a] + [P[a].get(b, 0) if a != b else "" for b in candidates]
        w.writerow(row)
    return out.getvalue()

@app.route("/public/<eid>/results.csv")
def public_results_csv(eid: str):
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
def public_pairwise_csv(eid: str):
    ballots = load_ballots(eid)
    candidates = load_candidates()
    if not ballots:
        core = [c for c in candidates if c not in (RESERVED_BLANK, RESERVED_NULL)]
        header = "candidate," + ",".join(core)
        return Response(header + "\n", mimetype="text/csv")
    # gera pairwise apenas para candidatos "core"
    core = [c for c in candidates if c not in (RESERVED_BLANK, RESERVED_NULL)]
    _, pairwise, _ = schulze_ranking_from_ballots(ballots, candidates)
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["candidate"] + core)
    for a in core:
        row = [a] + [pairwise[a].get(b, 0) if a != b else "" for b in core]
        w.writerow(row)
    resp = Response(out.getvalue(), mimetype="text/csv")
    resp.headers["Content-Disposition"] = f'attachment; filename="pairwise_{eid}.csv"'
    return resp

# =============== Painel Admin (UI) ===============
@app.route("/admin/home")
def admin_home():
    if not require_admin(request):
        abort(403)
    secret_qs = (request.args.get("secret") or "")
    eid = get_current_election_id()
    tmpl = """
    <!doctype html>
    <html lang="pt-BR">
    <head>
      <meta charset="utf-8"><title>Admin · Painel</title>
      <style>
        body{font-family:system-ui;padding:24px;line-height:1.35}
        h1{margin-top:0}
        .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
        .card{border:1px solid #e5e7eb;border-radius:10px;padding:14px;background:#fafafa}
        a.btn{display:inline-block;margin-top:6px;padding:8px 10px;border:1px solid #ddd;background:#eee;border-radius:8px;text-decoration:none;color:#111}
        a.btn:hover{filter:brightness(0.96)}
        code{background:#f3f4f6;padding:2px 6px;border-radius:6px}
      </style>
    </head>
    <body>
      <h1>Admin · Painel</h1>
      <p><b>Votação atual (EID):</b> <code>{{ eid }}</code></p>
      <div class="grid">
        <div class="card">
          <h3>Configurações</h3>
          <p><a class="btn" href="/admin/candidates?secret={{ s|e }}">Candidatos &amp; Prazos</a></p>
          <p><a class="btn" href="/admin/election_meta?secret={{ s|e }}">Metadados da votação</a></p>
        </div>
        <div class="card">
          <h3>Chaves &amp; Usuários</h3>
          <p><a class="btn" href="/admin/assign_ui?secret={{ s|e }}">Atribuir chaves (UI leve)</a></p>
          <p><a class="btn" href="/admin/users_list?secret={{ s|e }}">Ver usuários (JSON)</a></p>
          <p><a class="btn" href="/admin/keys_list?secret={{ s|e }}">Ver chaves (JSON)</a></p>
          <p><a class="btn" href="/admin/trash_list?secret={{ s|e }}">Lixeira (JSON)</a></p>
        </div>
        <div class="card">
          <h3>Auditoria</h3>
          <p><a class="btn" href="/admin/audit_preview?secret={{ s|e }}">Prévia (UI)</a></p>
          <p><a class="btn" href="/public/{{ eid }}/audit">Log público atual</a></p>
        </div>
        <div class="card">
          <h3>Downloads</h3>
          <p><a class="btn" href="/admin/export_audit_bundle?secret={{ s|e }}">Pacote de Auditoria (ZIP)</a></p>
          <p><a class="btn" href="/admin/backup_zip?secret={{ s|e }}">Backup completo (ZIP)</a></p>
          <p>
            <form action="/admin/backup_zip_eid" method="get" style="display:flex;gap:6px;align-items:center">
              <input type="hidden" name="secret" value="{{ s|e }}">
              <input type="text" name="eid" placeholder="EID específico" value="{{ eid|e }}">
              <button>Backup por EID</button>
            </form>
          </p>
        </div>
      </div>
      <p style="margin-top:18px"><a href="/">Início</a></p>
    </body>
    </html>
    """
    return render_template_string(tmpl, s=secret_qs, eid=eid)

# =============== Admin: Candidatos & Prazo (UI) ===============
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
        .row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
        .btn{padding:8px 10px;border:1px solid #ddd;background:#eee;border-radius:8px;text-decoration:none;color:#111}
        .btn:hover{filter:brightness(0.96)}
        select,input{margin-left:4px}
      </style>
    </head>
    <body>
      <div class="row" style="justify-content:space-between;margin-bottom:10px">
        <h1 style="margin:0">Admin · Candidatos &amp; Prazo</h1>
        {% if secret_qs %}<a class="btn" href="/admin/home?secret={{ secret_qs|e }}">Voltar ao painel</a>{% endif %}
      </div>

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

# =============== Admin: Election Meta (UI) ===============
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

    tmpl = """
    <!doctype html>
    <html lang="pt-BR">
    <head>
      <meta charset="utf-8"><title>Admin · Metadados</title>
      <style>
        body{font-family:system-ui;padding:24px}
        label{display:block;margin:6px 0}
        input,select{margin-left:4px}
        .msg{color:green}
        .warn{color:#b45309}
        a.btn{padding:8px 10px;border:1px solid #ddd;background:#eee;border-radius:8px;text-decoration:none;color:#111}
      </style>
    </head>
    <body>
      <div style="display:flex;justify-content:space-between;align-items:center">
        <h1 style="margin:0">Admin · Metadados da votação</h1>
        {% if secret_qs %}<a class="btn" href="/admin/home?secret={{ secret_qs|e }}">Voltar</a>{% endif %}
      </div>
      {% if msg %}<p class="msg">{{ msg }}</p>{% endif %}
      {% if warn %}<p class="warn">{{ warn }}</p>{% endif %}

      <form method="POST">
        <label>EID: <input name="eid" value="{{ election_id|e }}"></label>
        <label>Título: <input name="title" value="{{ meta.title if meta else '' }}"></label>
        <label>Data (YYYY-MM-DD): <input name="date" value="{{ meta.date if meta else '' }}"></label>
        <label>Hora (HH:MM): <input name="time" value="{{ meta.time if meta else '' }}"></label>
        <label>Fuso:
          <select name="tz">
            {% for tz in tz_options %}
              <option value="{{ tz }}" {% if meta and meta.tz==tz %}selected{% endif %}>{{ tz }}</option>
            {% endfor %}
          </select>
        </label>
        <label>Categoria: <input name="category" value="{{ meta.category if meta else '' }}"></label>
        <button>Salvar</button>
      </form>

      <p style="margin-top:14px"><a href="/">Início</a></p>
    </body>
    </html>
    """
    return render_template_string(
        tmpl,
        msg=msg, warn=warn,
        election_id=d.get("election_id","default"),
        meta=meta or {},
        tz_options=tz_opts_list,
        secret_qs=request.args.get('secret','')
    )

# =============== Admin: UIs leves auxiliares ===============
@app.route("/admin/assign_ui")
def admin_assign_ui():
    if not require_admin(request): abort(403)
    tmpl = """
    <!doctype html><meta charset="utf-8">
    <title>Admin · Atribuir chaves (UI leve)</title>
    <style>
      body{font-family:system-ui;padding:24px;line-height:1.35}
      input{padding:6px;border:1px solid #ddd;border-radius:6px}
      button{padding:8px 10px;border:1px solid #ddd;background:#eee;border-radius:8px}
      code{background:#f3f4f6;padding:2px 6px;border-radius:6px}
    </style>
    <h1>Admin · Atribuir chaves</h1>
    <p>Use as URLs abaixo (GET) para atribuir chaves:</p>
    <ul>
      <li><b>Gerar</b>: <code>/admin/assign_batch_generate?secret=SEU&amp;ras=user1,user2&amp;peso=1</code></li>
      <li><b>Usar pool</b>: <code>/admin/assign_batch_use_pool?secret=SEU&amp;ras=user1,user2</code></li>
    </ul>
    <p style="margin-top:10px"><a href="/admin/home?secret={{ secret|e }}">Voltar ao painel</a></p>
    """
    return render_template_string(tmpl, secret=(request.args.get("secret") or ""))

@app.route("/admin/audit_preview")
def admin_audit_preview():
    if not require_admin(request): abort(403)
    eid = (request.args.get("eid") or get_current_election_id()).strip()
    tmpl = """
    <!doctype html><meta charset="utf-8">
    <title>Admin · Prévia de Auditoria</title>
    <style>
      body{font-family:system-ui;padding:24px;line-height:1.35}
      pre{white-space:pre-wrap;background:#f9fafb;border:1px solid #e5e7eb;padding:10px;border-radius:8px}
      code{background:#f3f4f6;padding:2px 6px;border-radius:6px}
      a.btn{padding:8px 10px;border:1px solid #ddd;background:#eee;border-radius:8px;text-decoration:none;color:#111}
    </style>
    <h1>Admin · Prévia de Auditoria</h1>
    <p>Votação atual: <code>{{ eid }}</code></p>
    <p><a class="btn" href="/admin/audit_raw?secret={{ secret|e }}&eid={{ eid|e }}">Baixar JSON do log</a></p>
    <p><a class="btn" href="/admin/ballots_raw?secret={{ secret|e }}&eid={{ eid|e }}">Baixar JSON das cédulas</a></p>
    <p style="margin-top:10px"><a href="/admin/home?secret={{ secret|e }}">Voltar</a></p>
    """
    return render_template_string(tmpl, secret=(request.args.get("secret") or ""), eid=eid)

# =============== Admin: JSON endpoints de apoio ===============
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

# =============== Admin: Operações em lote (atribuição de chaves, pesos, exclusões) ===============
def _assign_key_to_user(reg, keys_doc, user, key, peso=None):
    u = reg["users"].get(user, {"used": False, "peso": 1, "attempts": {}})
    u["key"] = key
    if peso is not None:
        u["peso"] = int(peso)
    reg["users"][user] = u
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
        alphabet = string.ascii_uppercase + string.digits
        parts = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)]
        return "-".join(parts)

    assigned = []
    for u in users:
        for _ in range(1000):
            k = gen_key()
            if k not in keys_doc["keys"] and k not in keys_doc.get("pool", []):
                _assign_key_to_user(reg, keys_doc, u, k, peso=peso)
                assigned.append((u, k))
                break

    save_registry(reg); save_keys(keys_doc)
    eid = get_current_election_id()
    audit_admin(eid, "ASSIGN_GENERATE", f"count={len(assigned)}", request.remote_addr or "-")
    return Response("\n".join(f"{u},{k}" for (u, k) in assigned) or "(nada a atribuir)", mimetype="text/plain; charset=utf-8")

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
        if not pool: break
        k = pool.pop(0)
        _assign_key_to_user(reg, keys_doc, u, k)
        assigned.append((u, k))

    keys_doc["pool"] = pool
    save_registry(reg); save_keys(keys_doc)
    eid = get_current_election_id()
    audit_admin(eid, "ASSIGN_FROM_POOL", f"count={len(assigned)}", request.remote_addr or "-")
    return Response("\n".join(f"{u},{k}" for (u, k) in assigned) or "(pool esgotado ou nada a atribuir)", mimetype="text/plain; charset=utf-8")

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
    audit_admin(get_current_election_id(), "SET_USER_WEIGHT", f"user={user} peso={u['peso']}", request.remote_addr or "-")
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
    audit_admin(get_current_election_id(), "DELETE_USER", f"user={user}", request.remote_addr or "-")
    return Response('{"ok":true}', mimetype="application/json")

# ... (outros endpoints de batch delete, restore, empty trash seguem o mesmo padrão) ...

# =============== Admin: Downloads de auditoria e backup ===============
def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""): h.update(chunk)
    return h.hexdigest()

@app.route("/admin/export_audit_bundle")
def admin_export_audit_bundle():
    if not require_admin(request): abort(403)
    eid = (request.args.get("eid") or get_current_election_id()).strip()
    paths = []
    bpath, apath = ballots_path(eid), audit_path(eid)
    if bpath.exists(): paths.append(("ballots/" + bpath.name, bpath))
    if apath.exists(): paths.append(("audit/" + apath.name, apath))
    for name in [CAND_FILE, ELECTION_FILE, VOTER_KEYS_FILE, REGISTRY_FILE, TRASH_FILE]:
        p = Path(name)
        if p.exists(): paths.append(("config/" + p.name, p))
    manifest = {"eid": eid, "generated_at_utc": datetime.utcnow().isoformat() + "Z", "files": []}
    for arcname, p in paths:
        try:
            manifest["files"].append({"arcname": arcname, "size": p.stat().st_size, "sha256": _sha256_file(p)})
        except Exception as e:
            manifest["files"].append({"arcname": arcname, "error": str(e)})
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for arcname, p in paths: z.write(p, arcname)
        z.writestr("README.txt", f"SchulzeVote - Pacote de Auditoria\nEID: {eid}\nArquivos principais incluídos.\n")
        z.writestr("MANIFEST.json", json.dumps(manifest, ensure_ascii=False, indent=2))
    buf.seek(0)
    resp = Response(buf.getvalue(), mimetype="application/zip")
    resp.headers["Content-Disposition"] = f'attachment; filename="audit_bundle_{eid}.zip"'
    return resp

# =============== Admin: Dados crus para depuração ===============
@app.route("/admin/audit_raw")
def admin_audit_raw():
    if not require_admin(request): abort(403)
    eid = (request.args.get("eid") or get_current_election_id()).strip()
    p = audit_path(eid)
    meta = get_election_meta(eid)
    lines = []
    if p.exists():
        with open(p, "r", encoding="utf-8") as f: lines = [ln.rstrip("\n") for ln in f]
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

# =============== Debug local ===============
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
