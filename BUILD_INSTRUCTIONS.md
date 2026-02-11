# Prism Chat - Build Instructions

## Requirements

- Python 3.8 or higher
- pip (Python package manager)

## Installation

1. Install required dependencies:
```bash
pip install pycryptodome pyinstaller
```

## Building the Executable

### Method 1: Using Batch Files (Easy)

**For Release Build (no console window):**
```bash
build_release.bat
```
- Output: `dist\Prism Chat.exe`
- No console window
- Debug logs disabled (set `DEBUG_MODE = False` in prism_client.py)

**For Debug Build (with console):**
```bash
build_debug.bat
```
- Output: `dist\Prism Chat Debug.exe`
- Shows console with debug logs
- Useful for troubleshooting

### Method 2: Manual PyInstaller Commands

**Release build:**
```bash
pyinstaller --onefile --noconsole --name "Prism Chat" prism_client.py
```

**Debug build:**
```bash
pyinstaller --onefile --name "Prism Chat Debug" prism_client.py
```

**Using the spec file:**
```bash
pyinstaller prism_chat.spec
```

## Build Options Explained

- `--onefile` - Creates a single .exe file
- `--noconsole` - Hides the console window (GUI only)
- `--name` - Sets the executable name
- `--icon=icon.ico` - Adds an icon (if you have one)

## Debug Mode

To enable/disable debug logging, edit `prism_client.py` and change:

```python
DEBUG_MODE = True   # Enable debug logs
DEBUG_MODE = False  # Disable debug logs (for release)
```

## Output Files

After building, you'll find:
- **Executable:** `dist\Prism Chat.exe`
- **Build files:** `build\` (can be deleted)
- **Spec file:** `Prism Chat.spec` (for rebuilding)

## Distribution

The `.exe` file in the `dist\` folder is **standalone** and can be distributed to any Windows computer without requiring Python installation.

### File Size Optimization

To reduce file size, you can use:
- **UPX compression:** `--upx-dir=path\to\upx`
- **Exclude unused modules:** Add to spec file

## Troubleshooting

### "pycryptodome not found"
```bash
pip install pycryptodome
```

### "pyinstaller not found"
```bash
pip install pyinstaller
```

### Antivirus False Positives
PyInstaller executables sometimes trigger antivirus warnings. This is a false positive. You can:
- Submit to antivirus vendors for whitelisting
- Sign the executable with a code signing certificate

### Missing DLLs
If users report missing DLL errors, use `--onedir` instead of `--onefile`:
```bash
pyinstaller --onedir --noconsole --name "Prism Chat" prism_client.py
```

## Advanced: Adding an Icon

1. Create or download a `.ico` file
2. Save it in the project directory
3. Use: `--icon=myicon.ico` when building

## Testing the Build

1. Build the executable
2. Copy `Prism Chat.exe` to a different computer (or VM)
3. Run it without Python installed
4. Verify all features work correctly
