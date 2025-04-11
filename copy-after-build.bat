@echo off
echo Copying extra files to dist...

xcopy /E /I /Y start-simulator.bat dist\
xcopy /E /I /Y stop-simulator.bat dist\
xcopy /E /I /Y backend dist\backend\
xcopy /E /I /Y frontend dist\frontend\

echo Done!
pause
