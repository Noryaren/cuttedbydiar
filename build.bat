@echo off
TITLE Build cuttedbydiar Executables (.exe)
COLOR 0A
echo ========================================================
echo         Building cuttedbydiar Executables for Windows
echo ========================================================
echo.

:: Check for administrator privileges
NET SESSION >nul 2>&1
if %errorLevel% NEQ 0 (
    echo [!] WARNING: It is recommended to run this script as Administrator.
    echo.
)

echo [1/3] Installing Python dependencies (scapy, pyinstaller)...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if %errorLevel% NEQ 0 (
    echo [X] Failed to install dependencies. Please check your Python/pip installation.
    pause
    exit /b %errorLevel%
)

echo.
echo [2/3] Building GUI Executable (cuttedbydiar-gui.exe)...
pyinstaller --noconsole --onefile --name="cuttedbydiar-gui" run.py
if %errorLevel% NEQ 0 (
    echo [X] Failed to build GUI executable.
    pause
    exit /b %errorLevel%
)

echo.
echo [3/3] Building CLI Executable (cuttedbydiar-cli.exe)...
pyinstaller --console --onefile --name="cuttedbydiar-cli" run.py
if %errorLevel% NEQ 0 (
    echo [X] Failed to build CLI executable.
    pause
    exit /b %errorLevel%
)

echo.
echo ========================================================
echo [SUCCESS] Build completed successfully!
echo Executables are located in the "dist" folder:
echo   - dist\cuttedbydiar-gui.exe  (Graphical Interface)
echo   - dist\cuttedbydiar-cli.exe  (Command Line Interface)
echo ========================================================
echo.
pause
