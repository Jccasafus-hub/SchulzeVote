from flask import Flask, jsonify, request
import os
import psycopg

app = Flask(__name__)


def get_db_connection():
    return psycopg.connect(os.environ["DATABASE_URL"])


@app.route("/api/status")
def status():
    return jsonify({
        "app": "SchulzeVote",
        "status": "online"
    })


@app.route("/api/elections", methods=["GET", "POST"])
def elections():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}

        title = (data.get("title") or "").strip()
        description = (data.get("description") or "").strip()
        timezone = (data.get("timezone") or "America/Sao_Paulo").strip()

        if not title:
            return jsonify({
                "error": "Title is required"
            }), 400

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO elections (
                        title,
                        description,
                        status,
                        timezone
                    )
                    VALUES (%s, %s, %s, %s)
                    RETURNING
                        id,
                        title,
                        description,
                        status,
                        starts_at,
                        ends_at,
                        timezone,
                        created_at
                """, (
                    title,
                    description or None,
                    "draft",
                    timezone
                ))

                row = cur.fetchone()

        return jsonify({
            "id": str(row[0]),
            "title": row[1],
            "description": row[2],
            "status": row[3],
            "starts_at": row[4].isoformat() if row[4] else None,
            "ends_at": row[5].isoformat() if row[5] else None,
            "timezone": row[6],
            "created_at": row[7].isoformat() if row[7] else None
        }), 201

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    id,
                    title,
                    description,
                    status,
                    starts_at,
                    ends_at,
                    timezone,
                    created_at
                FROM elections
                ORDER BY created_at DESC
            """)

            rows = cur.fetchall()

    result = []

    for row in rows:
        result.append({
            "id": str(row[0]),
            "title": row[1],
            "description": row[2],
            "status": row[3],
            "starts_at": row[4].isoformat() if row[4] else None,
            "ends_at": row[5].isoformat() if row[5] else None,
            "timezone": row[6],
            "created_at": row[7].isoformat() if row[7] else None
        })

    return jsonify({
        "elections": result
    })


@app.route("/api/elections/<election_id>")
def election_detail(election_id):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    id,
                    title,
                    description,
                    status,
                    starts_at,
                    ends_at,
                    timezone,
                    created_at
                FROM elections
                WHERE id = %s
            """, (election_id,))

            row = cur.fetchone()

    if row is None:
        return jsonify({
            "error": "Election not found"
        }), 404

    return jsonify({
        "id": str(row[0]),
        "title": row[1],
        "description": row[2],
        "status": row[3],
        "starts_at": row[4].isoformat() if row[4] else None,
        "ends_at": row[5].isoformat() if row[5] else None,
        "timezone": row[6],
        "created_at": row[7].isoformat() if row[7] else None
    })


@app.route("/api/elections/<election_id>/contests", methods=["GET", "POST"])
def contests(election_id):
    if request.method == "POST":
        data = request.get_json(silent=True) or {}

        title = (data.get("title") or "").strip()
        description = (data.get("description") or "").strip()

        voting_method = (data.get("voting_method") or "schulze").strip()
        ballot_type = (data.get("ballot_type") or "ranking").strip()
        secrecy_mode = (data.get("secrecy_mode") or "secret").strip()

        quorum_type = (data.get("quorum_type") or "none").strip()
        quorum_value = data.get("quorum_value")
        quorum_basis = (data.get("quorum_basis") or "voters").strip()

        display_vote_weight = bool(data.get("display_vote_weight", False))

        if not title:
            return jsonify({
                "error": "Title is required"
            }), 400

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id
                    FROM elections
                    WHERE id = %s
                """, (election_id,))

                if cur.fetchone() is None:
                    return jsonify({
                        "error": "Election not found"
                    }), 404

                cur.execute("""
                    INSERT INTO contests (
                        election_id,
                        title,
                        description,
                        voting_method,
                        ballot_type,
                        secrecy_mode,
                        display_vote_weight,
                        quorum_type,
                        quorum_value,
                        quorum_basis
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING
                        id,
                        election_id,
                        title,
                        description,
                        voting_method,
                        ballot_type,
                        secrecy_mode,
                        display_vote_weight,
                        quorum_type,
                        quorum_value,
                        quorum_basis,
                        position,
                        created_at
                """, (
                    election_id,
                    title,
                    description or None,
                    voting_method,
                    ballot_type,
                    secrecy_mode,
                    display_vote_weight,
                    quorum_type,
                    quorum_value,
                    quorum_basis
                ))

                row = cur.fetchone()

        return jsonify({
            "id": str(row[0]),
            "election_id": str(row[1]),
            "title": row[2],
            "description": row[3],
            "voting_method": row[4],
            "ballot_type": row[5],
            "secrecy_mode": row[6],
            "display_vote_weight": row[7],
            "quorum_type": row[8],
            "quorum_value": float(row[9]) if row[9] is not None else None,
            "quorum_basis": row[10],
            "position": row[11],
            "created_at": row[12].isoformat() if row[12] else None
        }), 201

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    id,
                    election_id,
                    title,
                    description,
                    voting_method,
                    ballot_type,
                    secrecy_mode,
                    display_vote_weight,
                    quorum_type,
                    quorum_value,
                    quorum_basis,
                    position,
                    created_at
                FROM contests
                WHERE election_id = %s
                ORDER BY position ASC, created_at ASC
            """, (election_id,))

            rows = cur.fetchall()

    result = []

    for row in rows:
        result.append({
            "id": str(row[0]),
            "election_id": str(row[1]),
            "title": row[2],
            "description": row[3],
            "voting_method": row[4],
            "ballot_type": row[5],
            "secrecy_mode": row[6],
            "display_vote_weight": row[7],
            "quorum_type": row[8],
            "quorum_value": float(row[9]) if row[9] is not None else None,
            "quorum_basis": row[10],
            "position": row[11],
            "created_at": row[12].isoformat() if row[12] else None
        })

    return jsonify({
        "contests": result
    })


if __name__ == "__main__":
    app.run(debug=True)
