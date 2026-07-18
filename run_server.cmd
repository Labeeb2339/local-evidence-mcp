@echo off
setlocal
set "PROJECT_ROOT=%~dp0"
set "PYTHONPATH=%PROJECT_ROOT%src;%PYTHONPATH%"

where py >nul 2>nul
if errorlevel 1 (
  python -m local_evidence_mcp.server %*
) else (
  py -3 -m local_evidence_mcp.server %*
)

