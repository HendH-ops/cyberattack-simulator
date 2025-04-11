@echo off
echo Starting Cyberattack Simulator...

:: Start Flask backend
start "" cmd /k "cd backend && call venv\Scripts\activate && python app.py"

:: Start React frontend
start "" cmd /k "cd frontend && npm start"

echo All systems launching...
