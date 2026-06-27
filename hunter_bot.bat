@echo off
title Bug Bounty Hunter Bot
cd /d "%~dp0"
echo  _   _       _
echo ^| ^| ^| ^|     ^| ^|
echo ^| ^|__^| ^|_   _^| ^|_ _   _ _ __   ___
echo ^|  __  ^| ^| ^| ^| __^| ^| ^| ^| '_ \ / _ \
echo ^| ^|  ^| ^| ^|_^| ^| ^|_^| ^|_^| ^| ^|_) ^|  __/
echo ^|_^|  ^|_|\__,_|\__|\__,_| .__/ \___|
echo                         ^| ^|
echo                         ^|_|
echo Autonomous Bug Bounty Hunter
echo.
set PY=C:\Users\salva\AppData\Local\Programs\Python\Python312\python.exe
%PY% hunter_bot.py
echo.
pause
