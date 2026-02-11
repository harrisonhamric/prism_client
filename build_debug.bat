@echo off
echo ===================================
echo Building Prism Chat (Debug Mode)
echo ===================================
echo.

echo Cleaning previous builds...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist "Prism Chat.spec" del "Prism Chat.spec"

echo.
echo Building executable with console...
pyinstaller --onefile --name "Prism Chat Debug" prism_client.py

echo.
echo ===================================
echo Build complete!
echo ===================================
echo.
echo Executable location: dist\Prism Chat Debug.exe
echo.
pause
