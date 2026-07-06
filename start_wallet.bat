@echo off
title Sosaiem Wallet
cd /d "%~dp0"
set PY=python
where python >nul 2>nul || set PY=py
%PY% --version >nul 2>nul
if errorlevel 1 (
   echo.
   echo   Python is not installed yet.
   echo   Get it free at  https://python.org/downloads
   echo   IMPORTANT: tick "Add python.exe to PATH" during install, then run me again.
   echo.
   pause
   exit /b
)
%PY% -c "import dilithium_py, cryptography" >nul 2>nul
if errorlevel 1 (
   echo   First-time setup: installing Sosaiem's post-quantum signature library...
   %PY% -m pip install --quiet dilithium-py cryptography
)
echo   Starting the Sosaiem Wallet...
%PY% sosaiem_wallet.py %*
pause
