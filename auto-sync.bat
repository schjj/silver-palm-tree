@echo off
title Bug Bounty Auto-Sync
cd /d "%~dp0"
echo Auto-syncing %cd% to GitHub...
echo Every file change (.py, .bat, .md, .json) auto-commits and pushes
echo.
powershell -ExecutionPolicy Bypass -File "%~dp0auto-sync.ps1"
pause
