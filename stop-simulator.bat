@echo off
echo 🛑 Stopping Cyberattack Simulator...

:: Kill all Python processes (Flask backend)
echo Stopping Flask backend...
taskkill /F /IM python.exe /T

:: Kill all Node processes (React frontend)
echo Stopping React frontend...
taskkill /F /IM node.exe /T

echo ✅ All simulator processes stopped.
echo.
echo You can now start the simulator again using start-simulator.bat
pause
