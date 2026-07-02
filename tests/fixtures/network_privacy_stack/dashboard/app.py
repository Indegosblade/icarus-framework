"""Synthetic Flask dashboard fixture (references pihole for identify)."""
import flask
import requests

app = flask.Flask(__name__)


@app.route("/api/status")
def status():
    resp = requests.get("http://10.0.0.8:8080/api/stats/summary")
    return resp.json()
