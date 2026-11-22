@echo off
rem Run skillaudit from this folder without installing (Windows).
setlocal
set "PYTHONPATH=%~dp0;%PYTHONPATH%"
python -m skillaudit %*
exit /b %ERRORLEVEL%
