import base64

from flask import Flask, request, render_template
from logzero import logger

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/step1")
def step1():
    return render_template("step1.html")


@app.route("/step2/<target>")
def step2(target):
    return render_template("step2.html", target=target)


@app.route("/step3")
def step3():
    return render_template("step3.html")


@app.route("/b64/<data>")
def b64(data):
    try:
        data = data.encode()
        logger.info("RECEIVED DATA: %s", base64.decodebytes(data).decode())
    except Exception:
        pass

    return "OK"
