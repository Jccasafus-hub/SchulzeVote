from flask import Flask, jsonify
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


@app.route("/api/elections")
def elections():
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


if __name__ == "__main__":
    app.run(debug=True)
