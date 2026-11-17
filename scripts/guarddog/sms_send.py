#!/usr/bin/env python3
# Send a Guard Dog alert text through the infra-TAK console. Usage: sms_send.py "Subject" /path/to/body.txt
#
# ops #845: the console answers HTTPS only on 127.0.0.1:5001 (gunicorn runs with --certfile),
# but this script used to POST to plain http://. The call got no answer, the bare
# `except: pass` hid it, and no alert text left the box and nothing was logged. The Test SMS
# button calls the provider directly, so it passed while real alerts were dropped.
# Same order as send-alert-email.sh: HTTPS first (loopback, so no certificate check), then
# HTTP only when HTTPS got no answer at all. A console that answered with any HTTP status
# is not asked again: repeating the POST could send the same text twice.
import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

# CONSOLE_PORT is the same override send-alert-email.sh reads; the tests use it.
try:
    PORT = int(os.environ.get("CONSOLE_PORT", "5001"))
except ValueError:
    PORT = 5001
PATH = "/api/guarddog/send-sms"


def _log(msg):
    """One line to stderr and to the journal (the watch scripts discard stderr)."""
    try:
        print("sms_send: " + msg, file=sys.stderr)
    except Exception:
        pass
    try:
        subprocess.run(["logger", "-t", "guarddog-sms", "--", msg], timeout=5,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def _post(scheme, data):
    """Returns (http_status, error). http_status is None when there was no HTTP answer."""
    url = "%s://127.0.0.1:%d%s" % (scheme, PORT, PATH)
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    ctx = None
    if scheme == "https":
        # Loopback to our own console, which holds a self-signed certificate.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            return resp.status, None
    except urllib.error.HTTPError as e:
        return e.code, None          # the console answered
    except Exception as e:           # refused, TLS mismatch, timeout: no answer
        return None, "%s: %s" % (type(e).__name__, e)


def main(argv):
    if len(argv) < 3:
        return 0
    subj, path = argv[1], argv[2]
    try:
        with open(path) as f:
            body = f.read()
    except Exception:
        body = subj
    data = json.dumps({"subject": subj, "body": body}).encode()

    status, https_err = _post("https", data)
    http_err = None
    if status is None:
        status, http_err = _post("http", data)
    if status is None:
        _log("NOT SENT (console unreachable on :%d; https: %s; http: %s): %s"
             % (PORT, https_err, http_err, subj))
        return 3
    if status != 200:
        _log("NOT SENT (console answered HTTP %d): %s" % (status, subj))
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
