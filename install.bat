@echo off
echo Installing WiFi Sprite...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.7+ from https://python.org
    pause
    exit /b 1
)

echo Installing dependencies...
pip install -r requirements.txt

echo.
echo Installing WiFi Sprite as system utility...
pip install -e .

echo.
echo Installation complete!
echo You can now run: wifi-sprite
echo Or: python src\main.py
echo Or: run.bat
echo.
pause