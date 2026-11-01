@echo off
rem Hermes launcher.  Usage: run [start|stop|restart|status|test]   (default: start)
setlocal
cd /d "%~dp0"
set "PORT=8000"
set "HERMES=%~dp0.venv\Scripts\hermes.exe"
set "ACTION=%~1"
if "%ACTION%"=="" set "ACTION=start"

if not exist "%HERMES%" (
  echo Hermes is not installed here. Run these once:
  echo   python -m venv .venv
  echo   .venv\Scripts\pip install -e ".[dev]"
  echo   .venv\Scripts\hermes init
  exit /b 1
)

if /i "%ACTION%"=="start"   goto start
if /i "%ACTION%"=="stop"    goto stop
if /i "%ACTION%"=="restart" goto restart
if /i "%ACTION%"=="status"  goto status
if /i "%ACTION%"=="test"    goto test
echo Unknown action "%ACTION%". Use: start, stop, restart, status or test.
exit /b 2

:start
call :listening
if defined PID (
  echo Hermes is already running on port %PORT% ^(process %PID%^).
  goto open
)
start "Hermes server" /min "%HERMES%" serve --port %PORT%
echo Starting Hermes...
powershell -NoProfile -Command "for($i=0;$i -lt 20;$i++){ try { Invoke-WebRequest http://127.0.0.1:%PORT%/login -UseBasicParsing -TimeoutSec 2 | Out-Null; exit 0 } catch { Start-Sleep 1 } }; exit 1"
if errorlevel 1 (
  echo Hermes did not answer on port %PORT%. Run "%HERMES%" serve to see the error.
  exit /b 1
)
echo Hermes is running on http://127.0.0.1:%PORT%
:open
start "" http://127.0.0.1:%PORT%
exit /b 0

:stop
call :listening
if not defined PID (
  echo Hermes is not running.
  exit /b 0
)
taskkill /PID %PID% /F >nul
echo Stopped Hermes ^(process %PID%^).
exit /b 0

:restart
call :listening
if defined PID taskkill /PID %PID% /F >nul
timeout /t 2 >nul
goto start

:status
call :listening
if defined PID (echo Running on http://127.0.0.1:%PORT% ^(process %PID%^)) else (echo Not running)
"%HERMES%" status
exit /b 0

:test
".venv\Scripts\python.exe" -m pytest -q -p no:cacheprovider
exit /b %errorlevel%

:listening
set "PID="
for /f %%p in ('powershell -NoProfile -Command "(Get-NetTCPConnection -LocalPort %PORT% -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1).OwningProcess"') do set "PID=%%p"
exit /b 0
