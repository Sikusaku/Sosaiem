@echo off
title Build Sosaiem.exe
cd /d "%~dp0"
echo.
echo   Building the single Sosaiem app into one .exe...
echo.
set PY=python
where python >nul 2>nul || set PY=py
%PY% --version >nul 2>nul
if errorlevel 1 (
   echo   Python not found. Install from https://python.org/downloads
   echo   Tick "Add python.exe to PATH" during install, then run me again.
   pause & exit /b
)

echo   Installing build tools + libraries...
%PY% -m pip install --quiet --upgrade pyinstaller dilithium-py cryptography

echo   Packaging (this takes a couple of minutes)...
%PY% -m PyInstaller --onefile --console --name Sosaiem ^
  --collect-all cryptography --collect-all dilithium_py ^
  --add-data "wallet_ui.html;." ^
  --hidden-import portmap --hidden-import nostrseed ^
  sosaiem_app.py

echo.
if exist "dist\Sosaiem.exe" (
  echo   DONE. Your app is at:  dist\Sosaiem.exe
  echo   That single file is the whole thing: wallet, miner, explorer and node.
) else (
  echo   Build did not produce dist\Sosaiem.exe -- scroll up for the error.
)
echo.
pause
