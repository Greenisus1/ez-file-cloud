@echo off
cd /d "%~dp0"
where py >nul 2>nul
if not errorlevel 1 (
    py -3 ezfilecloud.py
) else (
    python ezfilecloud.py
)
pause
