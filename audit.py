import hmac, hashlib, os, json

SECRET_KEY = os.environ.get("SECRET_KEY", "changeme").encode()
AUDIT_FILE = "audit_log.jsonl"

def log_vote(voter_id, ranking, receipt):
    data = {"voter_id": voter_id, "ranking": ranking, "receipt": receipt}
    msg = json.dumps(data, sort_keys=True).encode()
    sig = hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()
    record = {"data": data, "sig": sig}
    with open(AUDIT_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")

def verify_receipt(receipt):
    if not os.path.exists(AUDIT_FILE):
        return False
    with open(AUDIT_FILE) as f:
        for line in f:
            record = json.loads(line)
            if record["data"]["receipt"] == receipt:
                msg = json.dumps(record["data"], sort_keys=True).encode()
                sig = hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()
                return sig == record["sig"]
    return False
