@echo off
chcp 65001 >nul
title Bug Bounty AI Agent
cd /d "%~dp0"
set PY=C:\Users\salva\AppData\Local\Programs\Python\Python312\python.exe
%PY% "%~dp0bb_agent.py"
if errorlevel 1 (
    echo.
    echo Press any key to exit...
    pause >nul
)
