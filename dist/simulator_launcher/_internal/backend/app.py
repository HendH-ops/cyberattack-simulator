import os
from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app)

LOG_FILE = "logs/simulation_report.txt"

# Fake attack simulations
def simulate_ddos():
    return "DDoS Attack: Traffic flooding the server."

def simulate_sql_injection():
    return "SQL Injection Attack: Attempting to bypass login."

def simulate_mitm():
    return "MITM Attack: Intercepting traffic between user and server."

@app.route('/attack', methods=['POST'])
def attack():
    data = request.json
    attack_type = data.get('attack_type')

    if attack_type == 'ddos':
        result = simulate_ddos()
    elif attack_type == 'sqli':
        result = simulate_sql_injection()
    elif attack_type == 'mitm':
        result = simulate_mitm()
    else:
        result = "Unknown attack type."

    # Log the attack to file
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] Attack Detected: {attack_type.upper()} → {result}\n")


    return jsonify({"result": result})

if __name__ == '__main__':
    print("⚙️ Flask is starting...")
    app.run(debug=True)
