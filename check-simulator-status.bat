@echo off
echo Checking Simulator Status...

tasklist | findstr /I "python.exe" >nul
if %errorlevel%==0 (
    echo Flask (backend) is RUNNING
) else (
    echo Flask (backend) is NOT running
)

tasklist | findstr /I "node.exe" >nul
if %errorlevel%==0 (
    echo React (frontend) is RUNNING
) else (
    echo React (frontend) is NOT running
)

pause
