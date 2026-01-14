@echo off
REM ProxyHunter Launcher Script for Windows
REM This script creates a virtual environment, installs dependencies if needed, and starts the application

echo 🚀 Iniciando ProxyHunter ...

@echo off
REM ProxyHunter Launcher Script for Windows
REM This script creates a virtual environment, installs dependencies if needed, and starts the application

echo 🚀 Iniciando ProxyHunter ...

REM Check if virtual environment exists
if not exist ".venv" (
    echo 📦 Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo ❌ Failed to create virtual environment
        pause
        exit /b 1
    )
)

echo ✅ Virtual environment found, activating...
call .venv\Scripts\activate.bat
if errorlevel 1 (
    echo ❌ Failed to activate virtual environment
    pause
    exit /b 1
)

echo 📦 Upgrading pip...
python -m pip install --upgrade pip

echo 📥 Installing/updating dependencies...
pip install -r config\requirements.txt
if errorlevel 1 (
    echo ❌ Failed to install dependencies
    pause
    exit /b 1
)

REM Check for AI config file
set AI_CONFIG="config\ai_config.json"
set AI_CONFIG_EXAMPLE="config\ai_config.example.json"

if not exist %AI_CONFIG% (
    echo 🔧 AI config file not found. Copying from example...
    copy %AI_CONFIG_EXAMPLE% %AI_CONFIG%
)

REM Start the application
echo 🎯 Iniciando ProxyHunter...
python scripts\pyside_proxy.py

pause