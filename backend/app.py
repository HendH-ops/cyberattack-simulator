from flask import Flask, request, jsonify
from flask_cors import CORS
import time
import random
import logging
import os
from datetime import datetime
import sys
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from collections import deque

app = Flask(__name__)
CORS(app)

# Configure logging
if not os.path.exists('logs'):
    os.makedirs('logs')
logging.basicConfig(
    filename='logs/simulation_report.txt',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Also log to console
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
app.logger.addHandler(console_handler)

@app.route('/')
def index():
    return jsonify({"status": "Cyberattack Simulator Backend is running"})

class AIDefenseSystem:
    def __init__(self):
        self.attack_history = deque(maxlen=100)  # Store last 100 attacks
        self.model = RandomForestClassifier(n_estimators=100)
        self.initialized = False
        
    def _prepare_attack_features(self, attack_data):
        """Convert attack data into numerical features"""
        features = []
        
        # Attack type encoding
        attack_types = ['ddos', 'sql', 'xss', 'scan', 'password', 'mitm']
        attack_type = [1 if attack_data['type'] == t else 0 for t in attack_types]
        
        # Time-based features
        hour = datetime.now().hour
        is_business_hours = 1 if 9 <= hour <= 17 else 0
        
        # Intensity/complexity features
        intensity = float(attack_data.get('intensity', 0.5))
        duration = float(attack_data.get('duration', 1))
        
        features = attack_type + [is_business_hours, intensity, duration]
        return np.array(features).reshape(1, -1)
    
    def analyze_attack(self, attack_data):
        """Analyze attack and provide AI insights"""
        # Convert attack data to features
        features = self._prepare_attack_features(attack_data)
        
        # If we don't have enough data, use rule-based analysis
        if not self.initialized:
            return self._rule_based_analysis(attack_data)
        
        # Predict attack success probability
        success_prob = self.model.predict_proba(features)[0][1]
        
        # Generate countermeasures based on attack type and probability
        countermeasures = self._generate_countermeasures(attack_data, success_prob)
        
        # Store attack data for learning
        self.attack_history.append({
            'features': features[0],
            'success': success_prob > 0.5
        })
        
        # Retrain model periodically
        if len(self.attack_history) >= 10:
            self._train_model()
        
        return {
            'risk_level': self._calculate_risk_level(success_prob),
            'success_probability': float(success_prob),
            'countermeasures': countermeasures,
            'ai_confidence': self._calculate_confidence()
        }
    
    def _rule_based_analysis(self, attack_data):
        """Fallback analysis when not enough data for ML"""
        attack_type = attack_data['type']
        base_risk = {
            'ddos': 0.7,
            'sql': 0.8,
            'xss': 0.6,
            'scan': 0.4,
            'password': 0.5,
            'mitm': 0.75
        }
        
        risk = base_risk.get(attack_type, 0.5)
        countermeasures = self._generate_countermeasures(attack_data, risk)
        
        return {
            'risk_level': self._calculate_risk_level(risk),
            'success_probability': risk,
            'countermeasures': countermeasures,
            'ai_confidence': 0.5  # Medium confidence for rule-based
        }
    
    def _calculate_risk_level(self, probability):
        """Convert probability to risk level"""
        if probability < 0.3:
            return 'LOW'
        elif probability < 0.7:
            return 'MEDIUM'
        else:
            return 'HIGH'
    
    def _generate_countermeasures(self, attack_data, risk_prob):
        """Generate specific countermeasures based on attack type and risk"""
        countermeasures = {
            'ddos': [
                'Enable DDoS protection service',
                'Increase bandwidth capacity',
                'Implement rate limiting',
                'Deploy traffic filtering'
            ],
            'sql': [
                'Update WAF rules',
                'Implement input validation',
                'Use prepared statements',
                'Regular security audits'
            ],
            'xss': [
                'Enable Content Security Policy',
                'Implement XSS filters',
                'Sanitize user inputs',
                'Regular security training'
            ],
            'scan': [
                'Configure firewall rules',
                'Hide service banners',
                'Implement port knocking',
                'Regular vulnerability scanning'
            ],
            'password': [
                'Implement 2FA',
                'Enforce strong password policy',
                'Add login rate limiting',
                'Use password manager'
            ],
            'mitm': [
                'Enforce HTTPS',
                'Implement certificate pinning',
                'Enable HSTS',
                'Regular SSL/TLS audits'
            ]
        }
        
        attack_type = attack_data['type']
        measures = countermeasures.get(attack_type, [])
        
        # Select number of countermeasures based on risk
        num_measures = 1 if risk_prob < 0.3 else (2 if risk_prob < 0.7 else 3)
        return random.sample(measures, min(num_measures, len(measures)))
    
    def _calculate_confidence(self):
        """Calculate AI system's confidence based on training data"""
        return min(0.3 + (len(self.attack_history) * 0.01), 0.9)
    
    def _train_model(self):
        """Train the ML model on collected data"""
        if len(self.attack_history) < 10:
            return
            
        X = np.array([d['features'] for d in self.attack_history])
        y = np.array([d['success'] for d in self.attack_history])
        
        self.model.fit(X, y)
        self.initialized = True

# Initialize AI system
ai_system = AIDefenseSystem()

class AttackSimulator:
    @staticmethod
    def simulate_attack(attack_type, target, params):
        """Simulate an attack with AI analysis"""
        # Original attack simulation logic
        attack_result = {
            'ddos': lambda: AttackSimulator.ddos_attack(target, params.get('duration', 10), params.get('intensity', 0.8)),
            'sql': lambda: AttackSimulator.sql_injection(target, params.get('query_type', 'union')),
            'xss': lambda: AttackSimulator.xss_attack(target, params.get('payload', '<script>alert("XSS")</script>')),
            'scan': lambda: AttackSimulator.network_scan(target, params.get('scan_type', 'full')),
            'password': lambda: AttackSimulator.password_crack(target, params.get('method', 'dictionary')),
            'mitm': lambda: AttackSimulator.mitm_attack(target)
        }.get(attack_type, lambda: {"error": "Invalid attack type"})()
        
        # Add AI analysis
        ai_analysis = ai_system.analyze_attack({
            'type': attack_type,
            'target': target,
            **params
        })
        
        # Combine results
        attack_result.update({
            'ai_analysis': ai_analysis
        })
        
        return attack_result

    @staticmethod
    def ddos_attack(target, duration, intensity):
        """Simulate DDoS attack with different intensities"""
        packets = int(intensity * 1000)
        logging.info(f"DDoS attack simulation started on {target} - Packets: {packets}")
        time.sleep(2)  # Simulate attack duration
        success_rate = random.uniform(0.7, 0.99)
        return {
            "success": True,
            "packets_sent": packets,
            "success_rate": success_rate,
            "target_status": "overwhelmed" if success_rate > 0.8 else "stressed"
        }

    @staticmethod
    def sql_injection(target, query_type):
        """Simulate SQL injection attacks"""
        attack_types = {
            "union": "UNION SELECT * FROM users",
            "boolean": "1=1 --",
            "time": "WAITFOR DELAY '0:0:5'",
            "error": "SELECT 1/0"
        }
        logging.info(f"SQL Injection attempt on {target} using {query_type}")
        time.sleep(1)
        return {
            "success": True,
            "query_used": attack_types.get(query_type, "custom"),
            "vulnerable_fields": ["username", "password", "search"],
            "data_exposed": random.randint(100, 1000)
        }

    @staticmethod
    def xss_attack(target, payload):
        """Simulate Cross-Site Scripting attacks"""
        logging.info(f"XSS attack simulation on {target}")
        return {
            "success": True,
            "payload_executed": payload,
            "vulnerable_elements": ["comment_field", "user_profile"],
            "impact": "medium" if random.random() > 0.5 else "high"
        }

    @staticmethod
    def network_scan(target, scan_type):
        """Simulate network scanning and reconnaissance"""
        ports = [21, 22, 80, 443, 3306, 5432]
        open_ports = random.sample(ports, random.randint(2, 5))
        services = {
            21: "FTP",
            22: "SSH",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            5432: "PostgreSQL"
        }
        return {
            "success": True,
            "open_ports": open_ports,
            "services": {port: services[port] for port in open_ports},
            "vulnerabilities": random.randint(1, 5)
        }

    @staticmethod
    def password_crack(target, method):
        """Simulate password cracking attempts"""
        methods = {
            "dictionary": {"time": 3, "success_rate": 0.7},
            "bruteforce": {"time": 5, "success_rate": 0.9},
            "rainbow": {"time": 2, "success_rate": 0.8}
        }
        attack_info = methods.get(method, methods["dictionary"])
        time.sleep(1)
        success = random.random() < attack_info["success_rate"]
        return {
            "success": success,
            "method_used": method,
            "time_taken": attack_info["time"],
            "password_found": "P@ssw0rd123!" if success else None
        }

    @staticmethod
    def mitm_attack(target):
        """Simulate Man-in-the-Middle attack"""
        captured_data = [
            "HTTP cookies",
            "Email credentials",
            "Banking session"
        ] if random.random() > 0.5 else ["HTTP cookies"]
        return {
            "success": True,
            "intercepted_data": captured_data,
            "duration": random.randint(10, 30),
            "encryption_broken": random.choice([True, False])
        }

simulator = AttackSimulator()

@app.route('/api/attack', methods=['POST'])
def simulate_attack():
    data = request.json
    attack_type = data.get('type', '').lower()
    target = data.get('target', 'default_target')
    params = {k: v for k, v in data.items() if k not in ['type', 'target']}
    
    try:
        result = simulator.simulate_attack(attack_type, target, params)
        result['timestamp'] = datetime.now().isoformat()
        logging.info(f"Attack simulation completed: {attack_type} on {target}")
        return jsonify(result)
    except Exception as e:
        logging.error(f"Attack simulation failed: {str(e)}")
        return jsonify({"error": str(e)}), 400

@app.route('/api/attacks', methods=['GET'])
def get_available_attacks():
    return jsonify({
        "attacks": [
            {
                "id": "ddos",
                "name": "DDoS Attack",
                "description": "Distributed Denial of Service attack simulation",
                "params": ["duration", "intensity"]
            },
            {
                "id": "sql",
                "name": "SQL Injection",
                "description": "Database injection attack simulation",
                "params": ["query_type"]
            },
            {
                "id": "xss",
                "name": "Cross-Site Scripting",
                "description": "Client-side code injection attack",
                "params": ["payload"]
            },
            {
                "id": "scan",
                "name": "Network Scan",
                "description": "Network reconnaissance and vulnerability scanning",
                "params": ["scan_type"]
            },
            {
                "id": "password",
                "name": "Password Cracking",
                "description": "Password attack simulation",
                "params": ["method"]
            },
            {
                "id": "mitm",
                "name": "Man in the Middle",
                "description": "Network traffic interception simulation",
                "params": []
            }
        ]
    })

if __name__ == '__main__':
    try:
        print("🚀 Starting Cyberattack Simulator Backend...")
        print("📝 Logging to:", os.path.abspath('logs/simulation_report.txt'))
        app.run(debug=True, host='0.0.0.0', port=5000)
    except Exception as e:
        print(f"❌ Error starting the server: {str(e)}")
        logging.error(f"Server start error: {str(e)}")
        sys.exit(1)
