#!/usr/bin/env python3
import urllib.request, json, sys
if len(sys.argv) < 3:
    sys.exit(0)
subj, path = sys.argv[1], sys.argv[2]
try:
    with open(path) as f: body = f.read()
except Exception:
    body = subj
data = json.dumps({"subject": subj, "body": body}).encode()
req = urllib.request.Request("http://127.0.0.1:5001/api/guarddog/send-sms", data=data, headers={"Content-Type": "application/json"}, method="POST")
try:
    urllib.request.urlopen(req, timeout=10)
except Exception:
    pass
