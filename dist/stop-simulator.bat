@echo off
echo 🛑 Stopping Cyberattack Simulator...

:: Kill Flask (python.exe)
taskkill /F /IM python.exe >nul 2>&1

:: Kill React (node.exe)
taskkill /F /IM node.exe >nul 2>&1

echo ✅ All simulator processes stopped.
pause
