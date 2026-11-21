AgentWatch til Windows
======================

1. Installer nmap (inkl. Npcap): winget install Insecure.Nmap
   eller hent installeren fra https://nmap.org/download.html
2. Dobbeltklik AgentWatch.exe
   - Første gang oprettes %USERPROFILE%\.agentwatch\config.yaml med dit lokale netværk
   - GUI'en åbner i browseren på http://127.0.0.1:8765
   - Luk konsolvinduet for at stoppe AgentWatch
3. Fuld scanning (OS-detektion, UDP): højreklik AgentWatch.exe -> "Kør som administrator"
4. Tillad Python/AgentWatch på "Private netværk", hvis Windows Firewall spørger
   (ellers virker mDNS/SSDP-discovery ikke)

Kommandolinje (PowerShell):
  .\AgentWatch.exe scan
  .\AgentWatch.exe devices
  .\AgentWatch.exe export -f cyclonedx -o inventory.cdx.json
  .\AgentWatch.exe mcp            (MCP-server til dit vurderings-setup)
  .\AgentWatch.exe analyze        (Claude-analytiker, kraever ANTHROPIC_API_KEY)

Windows SmartScreen kan advare, fordi exe-filen ikke er kodesigneret:
vaelg "Flere oplysninger" -> "Kør alligevel".
