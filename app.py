import os
import hmac, hashlib, json, uuid
from flask import Flask, render_template, request, redirect, url_for, flash

from schulze import schulze_method
from audit import log_vote, verify_receipt

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "changeme")

# --- Configurações ---
BALLOTS = {}         # cédulas
VOTERS = {}          # quem já votou
CANDIDATES = ["Alice", "Bob", "Charlie", "Voto em Branco", "Voto Nulo"]

# --- Rotas ---
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/vote", methods=["GET", "POST"])
def vote():
    if request.method == "POST":
        voter_id = request.form.get("voter_id")
        if not voter_id or voter_id in VOTERS:
            flash("Voto já registrado ou ID inválido", "error")
            return redirect(url_for("index"))

        ranking = request.form.getlist("ranking")
        if not ranking:
            flash("Nenhuma opção selecionada", "error")
            return redirect(url_for("index"))

        # registrar voto
        receipt = str(uuid.uuid4())
        BALLOTS[voter_id] = ranking
        VOTERS[voter_id] = True
        log_vote(voter_id, ranking, receipt)

        return render_template("receipt.html", receipt=receipt)

    return render_template("vote.html", candidates=CANDIDATES)

@app.route("/results")
def results():
    if not BALLOTS:
        return "Nenhum voto computado ainda."
    ranking = schulze_method(BALLOTS.values(), CANDIDATES)
    return render_template("results.html", ranking=ranking)

@app.route("/verify", methods=["GET","POST"])
def verify():
    if request.method == "POST":
        receipt = request.form.get("receipt")
        valid = verify_receipt(receipt)
        return render_template("verify.html", checked=True, valid=valid, receipt=receipt)
    return render_template("verify.html", checked=False)

if __name__ == "__main__":
    app.run(debug=True)
