# Cyber Attack Simulator

A web-based cyber attack simulation tool with AI-powered analysis. This project consists of a React frontend and Flask backend.

## Features

- Multiple attack type simulations (DDoS, SQL Injection, XSS, Brute Force)
- Real-time attack visualization
- AI-powered risk analysis
- Detailed attack results and countermeasures

## Project Structure

cyberattack-simulator/
├── backend/
│ ├── app.py # Flask backend server
│ └── requirements.txt # Python dependencies
└── frontend/
├── public/ # Static files
├── src/ # React source code
└── package.json # Node.js dependencies


## Setup Instructions

### Backend Setup

1. Create and activate a Python virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
cd backend
pip install -r requirements.txt
```

3. Start the Flask server:
```bash
python app.py
```

### Frontend Setup

1. Install Node.js dependencies:
```bash
cd frontend
npm install
```

2. Start the development server:
```bash
npm start
```

The application will be available at http://localhost:3000

## Technologies Used

- Frontend:
  - React
  - Ant Design
  - JavaScript/ES6+

- Backend:
  - Flask
  - Python
  - scikit-learn (for AI analysis)

## Contributing

Feel free to submit issues and pull requests.

## License

MIT License
