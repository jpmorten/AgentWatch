@echo off
rem Dobbeltklik for at installere AgentWatch
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
pause
