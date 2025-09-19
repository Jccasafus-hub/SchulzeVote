from flask import (
    render_template, request, redirect, url_for,
    flash, current_app, make_response, abort, Response
)
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import json, io, os, zipfile

# importa o blueprint criado no __init__.py
from . import admin_bp

# importa funções utilitárias e constantes já existentes no app principal
from app import (
    require_admin, load_candidates, save_candidates,
    load_election_doc, save_election_doc, set_election_meta,
    get_election_meta, get_current_election_id,
    save_deadline, load_deadline, RESERVED_BLANK, RESERVED_NULL,
    ballots_path, audit_path, load_ballots, audit_admin
)

# ================== ROTAS ==================

@admin_bp.route("/home")
def admin_home():
    """Página inicial do painel de administração"""
    secret = request.args.get("secret", "")
    return render_template("admin_home.html", secret=secret)


@admin_bp.route("/candidates", methods=["GET", "POST"])
def admin_candidates():
    """Gerenciar lista de candidatos e prazo da eleição"""
    if not require_admin(request):
        abort(403)

    msg = warn = None
    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "save_candidates":
            raw = request.form.get("lista", "")
            lines = [ln.strip() for ln in raw.splitlines()]
            save_candidates(lines)
            msg = "Candidatos salvos."
            audit_admin(get_current_election_id(), "SAVE_CAND", f"{len(lines)} candidatos", request.remote_addr or "-")
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
        deadline_html = f"<p><b>Prazo atual:</b> {local.strftime('%d/%m/%Y %H:%M')} {tz_default}</p>"
    else:
        deadline_html = "<p><i>Nenhum prazo definido.</i></p>"

    return render_template(
        "admin_candidates.html",
        msg=msg, warn=warn,
        RESERVED_BLANK=RESERVED_BLANK,
        RESERVED_NULL=RESERVED_NULL,
        core_text="\n".join(core),
        deadline_html=deadline_html,
        secret=request.args.get("secret", "")
    )


@admin_bp.route("/election_meta", methods=["GET", "POST"])
def admin_election_meta():
    """Editar metadados da eleição (título, data, categoria etc.)"""
    if not require_admin(request):
        abort(403)

    d = load_election_doc()
    msg = warn = None

    if request.method == "POST":
        eid   = (request.form.get("eid") or d.get("election_id", "default")).strip()
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
        election_id=d.get("election_id", "default"),
        meta=meta,
        tz_options=tz_opts_list,
        secret=request.args.get("secret", "")
    )
