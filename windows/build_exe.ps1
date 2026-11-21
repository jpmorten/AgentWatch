# Bygger dist\AgentWatch.exe med PyInstaller. Kør fra repo-roden:
#   powershell -ExecutionPolicy Bypass -File windows\build_exe.ps1
$ErrorActionPreference = "Stop"
python -m pip install --upgrade pip
python -m pip install ".[all]" pyinstaller
python -m PyInstaller --noconfirm --onefile --name AgentWatch --paths . `
  --collect-data agentwatch --collect-submodules agentwatch `
  --collect-submodules uvicorn --collect-all zeroconf `
  --collect-submodules mcp --collect-submodules anthropic `
  windows\agentwatch_entry.py
Write-Host "Faerdig: dist\AgentWatch.exe"
