from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/api/status")
def status():
    return jsonify({
        "app": "SchulzeVote",
        "status": "online"
    })


if __name__ == "__main__":
    app.run(debug=True)
