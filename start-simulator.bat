@echo off
echo Starting Cyberattack Simulator...

:: Check if Python virtual environment exists
if not exist "backend\venv\Scripts\activate.bat" (
    echo Error: Python virtual environment not found!
    echo Please make sure to set up the virtual environment first.
    pause
    exit /b 1
)

:: Check if frontend exists
if not exist "frontend\package.json" (
    echo Error: Frontend package.json not found!
    echo Please make sure the frontend is properly set up.
    pause
    exit /b 1
)

:: Start Flask backend
echo Starting Flask backend...
start "Flask Backend" cmd /k "cd backend && venv\Scripts\activate.bat && python app.py"

:: Wait for Flask to start
timeout /t 5 /nobreak > nul

:: Start React frontend
echo Starting React frontend...
start "React Frontend" cmd /k "cd frontend && npm start"

echo All systems launching...
echo Please wait while services start up...
echo.
echo The simulator will be available at: http://localhost:3000
echo.
pause
