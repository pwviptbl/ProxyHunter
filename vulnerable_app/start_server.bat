@echo off
setlocal

set VENV_DIR=.\venv

REM Verifica se o diretório do venv existe
IF NOT EXIST "%VENV_DIR%\Scripts\activate.bat" (
    echo "Ambiente virtual nao encontrado. Criando..."
    python -m venv %VENV_DIR%
    IF %ERRORLEVEL% NEQ 0 (
        echo "Erro ao criar o ambiente virtual. Verifique se o Python esta instalado e no PATH."
        exit /b 1
    )
)

echo "Ativando ambiente virtual..."
CALL "%VENV_DIR%\Scripts\activate.bat"

echo "Instalando dependencias..."
pip install -r requirements.txt

echo "Iniciando o servidor vulneravel..."
python vulnerable_server.py

endlocal