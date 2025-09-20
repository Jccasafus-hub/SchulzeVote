import os
import io
import csv
import json
import uuid
import secrets
import string
import hashlib
import zipfile
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Tuple

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, Response, abort, session
)
from werkzeug.security import generate_password_hash, check_password_hash

# ===================== App & Config =====================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "mude-isto")

# Versão para cache busting em templates
APP_VERSION = os.environ.get("APP_VERSION", datetime.utcnow().strftime("%Y%m%d%H%M%S"))
app.jinja_env.globals["APP_VERSION"] = APP_VERSION

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "troque-admin")
ID_SALT = os.environ.get("ID_SALT", "mude-este-salt")
app.config["ADMIN_SECRET"] = ADMIN_SECRET

# ===================== Caminhos & Arquivos =====================
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

# Candidatos especiais (sempre no fim)
RESERVED_BLANK = "Voto em Branco"
RESERVED_NULL  = "Voto Nulo"

# ===================== Utilitários =====================
def norm(s: str) -> str:
    return (s or "").strip().upper()

def _squash_spaces(s: str) -> str:
    return " ".join((s or "").strip().split())

def key_hash(k: str) -> str:
    return hashlib.sha256((ID_SALT + norm(k)).encode()).hexdigest()

def require_admin(req) -> bool:
    token = req.args.get("secret") or req.headers.get("X-Admin-Secret")
    return bool(ADMIN_SECRET and token == ADMIN_SECRET)

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

# ===================== Persistência de Domínio =====================
def _ensure_keys_doc():
    doc = _read_json(VOTER_KEYS_FILE, {})
    doc.setdefault("keys", {})   # "KEY": {"used": false, "used_at": iso?, "peso": int}
    doc.setdefault("pool", [])   # lista de chaves livres
    return doc

def load_keys():
    return _ensure_keys_doc()

def save_keys(doc):
    _write_json(VOTER_KEYS_FILE, doc)

def _ensure_registry():
    reg = _read_json(REGISTRY_FILE, {})
    reg.setdefault("users", {})  # "user": {"pwd_hash":..., "key": "...", "used": false, "peso": 1, "attempts": {eid:n}}
    return reg

def load_registry():
    return _ensure_registry()

def save_registry(reg):
    _write_json(REGISTRY_FILE, reg)

def load_trash():
    return _read_json(TRASH_FILE, {"users": {}})

def save_trash(t):
    _write_json(TRASH_FILE, t)

def _normalize_core_candidates(lst: List[str]) -> List[str]:
    # Normaliza, remove vazios e os especiais; devolve apenas o "core"
    base = [_squash_spaces(x) for x in lst if _squash_spaces(x)]
    base = [x for x in base if x not in (RESERVED_BLANK, RESERVED_NULL)]
    # únicos preservando ordem
    seen, out = set(), []
    for x in base:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def load_candidates() -> List[str]:
    core = _read_json(CAND_FILE, [])
    core = _normalize_core_candidates(core)
    # Sempre adiciona especiais no fim
    return core + [RESERVED_BLANK, RESERVED_NULL]

def save_candidates(lines: List[str]):
    core = _normalize_core_candidates(lines)
    _write_json(CAND_FILE, core)

# ===================== Eleição (ID atual, prazo, metadados) =====================
def load_election_doc():
    d = _read_json(ELECTION_FILE, {})
    d.setdefault("election_id", "default")
    d.setdefault("deadline_utc", None)
    d.setdefault("meta", {})  # meta[eid] = {title, date, time, tz, category, updated_at}
    return d

def save_election_doc(d):
    _write_json(ELECTION_FILE, d)

def get_current_election_id() -> str:
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
        "updated_at": datetime.utcnow().isoformat() + "Z",
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

def is_voting_open() -> bool:
    dl = load_deadline()
    if dl is None:
        return True
    return datetime.now(timezone.utc) < dl

# ===================== Auditoria & Cédulas =====================
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

# ===================== Método de Schulze =====================
def _pairwise_from_ballots(ballots: List[dict], candidates: List[str]) -> Dict[str, Dict[str, int]]:
    """
    P[a][b] = total de pesos de votos que preferem a sobre b.
    Considera apenas candidatos "core" (sem Branco/Nulo).
    """
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
                if isinstance(ra, int) and isinstance(rc, int):
                    if ra < rc:
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
      strongest_path S[a][b] (Schulze).
    """
    core = [c for c in candidates if c not in (RESERVED_BLANK, RESERVED_NULL)]
    if not core:
        return [], {}, {}
    P = _pairwise_from_ballots(ballots, core)

    # Matriz de forças S
    S = {a: {b: 0 for b in core} for a in core}
    for a in core:
        for b in core:
            if a == b:
                continue
            if P[a][b] > P[b][a]:
                S[a][b] = P[a][b]
            else:
                S[a][b] = 0

    # Atualização tipo Floyd–Warshall
    for i in core:
        for j in core:
            if i == j:
                continue
            for k in core:
                if i == k or j == k:
                    continue
                S[j][k] = max(S[j][k], min(S[j][i], S[i][k]))

    # Ordenação: a precede b se S[a][b] > S[b][a]
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

    ranked = sorted(core, key=cmp_to_key(_cmp))
    return ranked, P, S

# ===================== Rotas utilitárias/diagnóstico =====================
@app.route("/__health")
def __health():
    return Response('{"ok": true}', mimetype="application/json")

@app.route("/__routes")
def __routes():
    lines = []
    for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
        methods = ",".join(sorted(m for m in rule.methods if m in ("GET", "POST", "PUT", "DELETE", "PATCH")))
        lines.append(f"{methods or 'GET'}  {rule.rule}  -> {rule.endpoint}")
    return Response("<pre>" + "\n".join(lines) + "</pre>", mimetype="text/html")

# ===================== Handlers de erro com logging =====================
import logging
from logging import StreamHandler

if not app.logger.handlers:
    app.logger.addHandler(StreamHandler())
    app.logger.setLevel(logging.INFO)

@app.errorhandler(404)
def handle_404(e):
    app.logger.warning("404 on %s?%s", request.path, request.query_string.decode("utf-8", errors="ignore"))
    return Response(
        "<h3>404 • Página não encontrada</h3>"
        "<p>Para o painel admin, use <code>/admin/home?secret=SEU_ADMIN_SECRET</code>.</p>",
        status=404, mimetype="text/html"
    )

@app.errorhandler(500)
def handle_500(e):
    app.logger.exception("500 on %s", request.path)
    return Response(
        "<h3>Erro interno (500)</h3><p>Verifique os logs do servidor para detalhes.</p>",
        status=500, mimetype="text/html"
    )

# ===================== Rotas públicas principais =====================
@app.route("/")
def index():
    return render_template("index.html", get_current_election_id=get_current_election_id)

@app.route("/schulze_guide")
def schulze_guide():
    return render_template("schulze_guide.html")

@app.route("/schulze")
def schulze_alias():
    return redirect(url_for("schulze_guide"))

# ===================== Registro/Login =====================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user_id = (request.form.get("user_id") or "").strip()
        pw = (request.form.get("password") or "").strip()
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

@app.route("/login", methods=["GET", "POST"])
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

# ===================== Votação =====================
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

@app.route("/vote", methods=["GET", "POST"])
def vote():
    if not is_voting_open():
        return Response(
            "<h2>Votação encerrada</h2><p>O prazo expirou.</p><p><a href='/'>Início</a></p>",
            mimetype="text/html",
            status=403,
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
                f"ATTEMPT {datetime.utcnow().isoformat()}Z user={user_id} provided={voter_key} ip={request.remote_addr or '-'} count={n}",
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
            f"VOTE {datetime.utcnow().isoformat()}Z voter={voter_key_h} receipt={receipt} ip={request.remote_addr or '-'}",
        )

        return render_template("receipt.html", receipt=receipt, eid=eid)

    # GET
    return render_template("vote.html", candidates=candidates)

# ===================== Resultados & Auditoria pública =====================
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
        extra = ""
        if meta.get("date") and meta.get("time"):
            extra = f" • <b>Data/Hora:</b> {meta.get('date','')} {meta.get('time','')} {meta.get('tz','')}"
        head = f"<h1>{meta.get('title','Auditoria')}</h1><p><b>ID:</b> {eid}{extra}</p>"
    else:
        head = f"<h1>Auditoria</h1><p><b>ID:</b> {eid}</p>"
    if not p.exists():
        return Response(head + "<pre>(Sem auditoria para esta votação.)</pre>", mimetype="text/html")
    with open(p, "r", encoding="utf-8") as f:
        lines = f.readlines()
    return Response(head + "<pre>" + "".join(lines) + "</pre>", mimetype="text/html")

# ===================== /public/elections + CSV =====================
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
    for _eid in all_eids:
        m = metas.get(_eid, {})
        cat = (m.get("category", "") or "").strip()
        if cat_filter and cat.lower() != cat_filter:
            continue
        if not within_date(m):
            continue
        enriched.append({
            "eid": _eid,
            "title": m.get("title", ""),
            "date":  m.get("date", ""),
            "time":  m.get("time", ""),
            "tz":    m.get("tz", ""),
            "category": cat
        })

    enriched.sort(key=lambda x: x.get("date", ""), reverse=True)
    return Response(json.dumps({"elections": enriched}, ensure_ascii=False, indent=2), mimetype="application/json")

# ===================== Relatórios extras CSV =====================
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
    ranking, pairwise, _strength = schulze_ranking_from_ballots(ballots, candidates)
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

# ===================== Admin (UI) =====================
@app.route("/admin")
def admin_root():
    # Redireciona sempre para home preservando ?secret=...
    secret = request.args.get("secret", "")
    if secret:
        return redirect(f"/admin/home?secret={secret}")
    return redirect("/admin/home")

@app.route("/admin/home")
def admin_home():
    if not require_admin(request):
        return redirect(url_for("admin_login"))
    return render_template("admin_home.html", secret=request.args.get("secret", ""))

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        provided = (request.form.get("secret") or "").strip()
        if provided and provided == ADMIN_SECRET:
            return redirect(url_for("admin_home", secret=provided))
        flash("Chave inválida.", "error")
        return redirect(url_for("admin_login"))
    return render_template("admin_login.html")

@app.route("/admin/logout")
def admin_logout():
    secret = request.args.get("secret", "")
    flash("Sessão encerrada.", "info")
    if secret:
        return redirect(url_for("index") + f"?secret={secret}")
    return redirect(url_for("index"))

@app.route("/admin/candidates")
def admin_candidates():
    if not require_admin(request): abort(403)
    return render_template(
        "admin_candidates.html",
        secret=request.args.get("secret", ""),
        current_eid=get_current_election_id(),
        candidates=load_candidates(),
        deadline=load_deadline()
    )

@app.route("/admin/election_meta")
def admin_election_meta():
    if not require_admin(request): abort(403)
    return render_template(
        "admin_election_meta.html",
        secret=request.args.get("secret", ""),
        current_eid=get_current_election_id(),
        meta=get_election_meta(get_current_election_id())
    )

@app.route("/admin/assign_ui")
def admin_assign_ui():
    if not require_admin(request): abort(403)
    return render_template(
        "admin_assign_ui.html",
        secret=request.args.get("secret", ""),
        current_eid=get_current_election_id()
    )

@app.route("/admin/audit_preview")
def admin_audit_preview():
    if not require_admin(request): abort(403)
    return render_template(
        "admin_audit_preview.html",
        secret=request.args.get("secret", ""),
        current_eid=get_current_election_id()
    )

# ===================== Admin: JSON dumps =====================
@app.route("/admin/keys_list")
def admin_keys_list():
    if not require_admin(request): abort(403)
    doc = load_keys()
    return Response(json.dumps({"keys": doc.get("keys", {})}, ensure_ascii=False, indent=2),
                    mimetype="application/json")

@app.route("/admin/pool_list")
def admin_pool_list():
    if not require_admin(request): abort(403)
    doc = load_keys()
    return Response(json.dumps({"pool": doc.get("pool", [])}, ensure_ascii=False, indent=2),
                    mimetype="application/json")

@app.route("/admin/users_list")
def admin_users_list():
    if not require_admin(request): abort(403)
    reg = load_registry()
    return Response(json.dumps({"users": reg.get("users", {})}, ensure_ascii=False, indent=2),
                    mimetype="application/json")

@app.route("/admin/trash_list")
def admin_trash_list():
    if not require_admin(request): abort(403)
    t = load_trash()
    return Response(json.dumps({"users": t.get("users", {})}, ensure_ascii=False, indent=2),
                    mimetype="application/json")

# ===================== Admin: Bundles / Backups =====================
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
        paths.append((f"ballots/{bpath.name}", bpath))
    if apath.exists():
        paths.append((f"audit/{apath.name}", apath))
    for name in [CAND_FILE, ELECTION_FILE, VOTER_KEYS_FILE, REGISTRY_FILE, TRASH_FILE]:
        p = Path(name)
        if p.exists():
            paths.append((f"config/{p.name}", p))
    manifest = {"eid": eid, "generated_at_utc": datetime.utcnow().isoformat() + "Z", "files": []}
    for arcname, p in paths:
        try:
            manifest["files"].append({"arcname": arcname, "size": p.stat().st_size, "sha256": _sha256_file(p)})
        except Exception as e:
            manifest["files"].append({"arcname": arcname, "error": str(e)})
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for arcname, p in paths:
            z.write(p, arcname)
        z.writestr("README.txt", "SchulzeVote - Pacote de Auditoria\n")
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
        for fname in [CAND_FILE, ELECTION_FILE, VOTER_KEYS_FILE, REGISTRY_FILE, TRASH_FILE]:
            if os.path.exists(fname):
                z.write(fname, fname)
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

# ===================== Admin: Dados crus =====================
@app.route("/admin/audit_raw")
def admin_audit_raw():
    if not require_admin(request): abort(403)
    eid = (request.args.get("eid") or get_current_election_id()).strip()
    p = audit_path(eid)
    meta = get_election_meta(eid)
    if not p.exists():
        return Response(json.dumps({"eid": eid, "meta": meta, "lines": []}, ensure_ascii=False, indent=2),
                        mimetype="application/json")
    with open(p, "r", encoding="utf-8") as f:
        lines = [ln.rstrip("\n") for ln in f.readlines()]
    return Response(json.dumps({"eid": eid, "meta": meta, "lines": lines}, ensure_ascii=False, indent=2),
                    mimetype="application/json")

@app.route("/admin/ballots_raw")
def admin_ballots_raw():
    if not require_admin(request): abort(403)
    eid = (request.args.get("eid") or get_current_election_id()).strip()
    ballots = load_ballots(eid)
    return Response(json.dumps({"eid": eid, "ballots": ballots}, ensure_ascii=False, indent=2),
                    mimetype="application/json")

@app.route("/admin/ping")
def admin_ping():
    ok = require_admin(request)
    return Response(json.dumps({"ok": ok}, ensure_ascii=False),
                    status=200 if ok else 403, mimetype="application/json")

# ===================== Health / Diagnostics =====================
@app.route("/healthz")
@app.route("/ping")
def healthz():
    return Response('{"ok":true}', mimetype="application/json")

# ===================== Main (debug local) =====================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
