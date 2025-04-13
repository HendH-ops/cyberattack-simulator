# Cyber Attack Simulator

- Author: Hendrik Hollo

A web-based cyber attack simulation tool with AI-powered analysis built with Streamlit.

## Features

- Multiple attack type simulations (DDoS, SQL Injection, XSS, Brute Force)
- Real-time attack visualization
- AI-powered risk analysis
- Detailed attack results and countermeasures

## Project Structure

cyberattack-simulator/
├── Home.py           # Streamlit application
├── requirements.txt  # Python dependencies
└── README.md        # Project documentation

## Setup Instructions

1. Create and activate a Python virtual environment:
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the Streamlit application:
```bash
streamlit run Home.py
```

The application will be available at http://localhost:8501

## Technologies Used

- Streamlit
- Python
- scikit-learn (for AI analysis)
- NumPy (for data processing)

## Contributing

Feel free to submit issues and pull requests.

## License

MIT License
