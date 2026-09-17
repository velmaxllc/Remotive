@echo off
REM Remoto Stream host — run this on the desktop you want to play on.
cd /d "%~dp0"
python host.py --fps 60 --bitrate 20000 %*
pause
