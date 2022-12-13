::===============================================================
:: Script for building windows targets via ssh into Linux remote host
:: More info at:  go/ppn-windows-build
:: Usage: <WORKSPACE>\google3\privacy\net\krypton\windows\tools\build_remote.bat <REMOTE_HOST> <TARGETS>
::===============================================================
@echo off
setlocal
set folder=%~dp0
REM x:\google\src\cloud\<user_name>\<workspace>\...
for /f "tokens=6 delims=:\" %%i in ("%folder%") do set workspace=%%i
set remote=
if %1.==. (
  if exist %userprofile%\remote_host.txt (
    set /p remote=<%userprofile%\remote_host.txt
  ) else (
    echo Please specify a remote host by passing as argument or saving it ^
in %userprofile%\remote_host.txt
    exit /b -1
  )
) else (
    set remote=%1
)
set targets=
if %2.==. (
    echo Please specify targets by passing as argument
    exit /b -1
) else (
    set targets=%2
)
echo Building %workspace% on remote server %remote% ...
ssh %remote% "cd $(p4 g4d %workspace%) && blaze build --config=lexan %targets%"

if NOT %ERRORLEVEL%==0 exit /b -2