@echo off
REM Remotive Stream client — run this on the laptop. Usage: run-client.bat <DESKTOP-IP>
cd /d "%~dp0"
if "%~1"=="" ( set /p HOSTIP="Desktop IP (LAN or Tailscale 100.x.y.z): " ) else ( set HOSTIP=%~1 )
python client.py %HOSTIP% --fps 60 --bitrate 20000
pause
