# throwaway (ops #1014): proves CodeQL goes red. Never merge.
import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    os.system('ping -c 1 ' + host)
    return subprocess.check_output('nslookup ' + host, shell=True)
