@echo off
title Build Sosaiem apps

echo ============================================================
echo   Building Sosaiem into double-click apps.
echo   Run this once. It can take a few minutes. Please wait.
echo ============================================================
echo.

set PY=python
where python >nul 2>nul
if errorlevel 1 set PY=py

%PY% --version >nul 2>nul
if errorlevel 1 goto nopython

echo Installing build tools, please wait...
%PY% -m pip install --upgrade pip
%PY% -m pip install pyinstaller dilithium-py cryptography
echo.

echo Building Sosaiem-Wallet.exe ...
%PY% -m PyInstaller --onefile --console --name Sosaiem-Wallet --collect-all cryptography --collect-all dilithium_py sosaiem_wallet.py

echo.
echo Building Sosaiem-Miner.exe ...
%PY% -m PyInstaller --onefile --console --name Sosaiem-Miner --collect-all cryptography --collect-all dilithium_py sosaiem_miner.py

echo.
echo ============================================================
echo   DONE. Your two apps are in the  dist  folder:
echo       dist\Sosaiem-Wallet.exe   (a small console window opens with it - that is normal)
echo       dist\Sosaiem-Miner.exe
echo   Upload those two files to your website.
echo ============================================================
echo.
echo   If an app will not open, run this to see the reason:
echo       %PY% -m PyInstaller --onefile --name WalletDebug sosaiem_wallet.py
pause
exit /b

:nopython
echo.
echo   Python was not found on this PC.
echo   Install it from  https://python.org/downloads
echo   During setup, tick the box  Add python.exe to PATH
echo   Then run this file again.
pause
exit /b
