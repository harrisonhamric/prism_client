@echo off
echo ===================================
echo Building Prism Chat Release
echo ===================================
echo.

echo Cleaning previous builds...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist "Prism Chat.spec" del "Prism Chat.spec"

echo.
echo Building executable...
pyinstaller --onefile --noconsole --name "Prism Chat" prism_client.py

echo.
echo ===================================
echo Build complete!
echo ===================================
echo.
echo Executable location: dist\Prism Chat.exe
echo.
pause
