from flask import Flask, jsonify
from pathlib import Path
import json

app = Flask(__name__)

ROOT_DIR = Path(__file__).resolve().parent.parent
ELECTION_FILE = ROOT_DIR / "election.json"
BALLOT_DIR = ROOT_DIR / "data" / "ballots"


@app.route("/api/status")
def status():
    return jsonify({
        "app": "SchulzeVote",
        "status": "online"
    })


@app.route("/api/elections")
def elections():
    election_ids = set()
    metadata = {}

    if ELECTION_FILE.exists():
        try:
            data = json.loads(ELECTION_FILE.read_text(encoding="utf-8"))

            if isinstance(data, dict):
                metadata = data
                election_ids.update(data.keys())
        except (json.JSONDecodeError, OSError):
            pass

    if BALLOT_DIR.exists():
        for ballot_file in BALLOT_DIR.glob("*.json"):
            election_ids.add(ballot_file.stem)

    result = []

    for eid in sorted(election_ids):
        info = metadata.get(eid, {})

        if not isinstance(info, dict):
            info = {}

        result.append({
            "eid": eid,
            "title": info.get("title", eid),
            "date": info.get("date"),
            "time": info.get("time"),
            "tz": info.get("tz"),
            "category": info.get("category")
        })

    return jsonify({
        "elections": result
    })


@app.route("/api/elections/<eid>")
def election_detail(eid):
    if not ELECTION_FILE.exists():
        return jsonify({
            "error": "Election not found"
        }), 404

    try:
        data = json.loads(ELECTION_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return jsonify({
            "error": "Could not read election data"
        }), 500

    if not isinstance(data, dict) or eid not in data:
        return jsonify({
            "error": "Election not found"
        }), 404

    info = data[eid]

    if not isinstance(info, dict):
        info = {}

    return jsonify({
        "eid": eid,
        "title": info.get("title", eid),
        "date": info.get("date"),
        "time": info.get("time"),
        "tz": info.get("tz"),
        "category": info.get("category")
    })


if __name__ == "__main__":
    app.run(debug=True)
