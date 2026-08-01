@echo off
title Sosaiem
cd /d "%~dp0"
set PY=python
where python >nul 2>nul || set PY=py
%PY% --version >nul 2>nul
if errorlevel 1 (
   echo.
   echo   Python isn't installed yet.
   echo   Get it free at  https://python.org/downloads
   echo   Tick "Add python.exe to PATH" during install, then run me again.
   echo.
   pause
   exit /b
)
%PY% -c "import dilithium_py, cryptography" >nul 2>nul
if errorlevel 1 (
   echo   First-time setup: installing Sosaiem's signature library...
   %PY% -m pip install --quiet dilithium-py cryptography
)
echo   Starting Sosaiem... (a window will open in a moment)
%PY% sosaiem_app.py %*
pause
