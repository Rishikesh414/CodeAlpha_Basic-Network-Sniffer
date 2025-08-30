from flask import Flask, render_template, jsonify
import threading
from sniffer import start_sniffer, stop_sniffer, captured_packets, sniffing

app = Flask(__name__)
sniffer_thread = None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/packets")
def get_packets():
    return jsonify(captured_packets[-20:])  # last 20 packets

@app.route("/start")
def start_capture():
    global sniffer_thread
    if not sniffing:
        sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
        sniffer_thread.start()
    return "Started"

@app.route("/stop")
def stop_capture():
    stop_sniffer()
    return "Stopped"

if __name__ == "__main__":
    app.run(debug=True, port=5000)
