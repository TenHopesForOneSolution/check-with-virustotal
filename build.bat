@echo off
setlocal

cd /d "%~dp0\cmd\check-with-virustotal"

echo Generating resources...
go generate

echo Building...
go build -ldflags="-H windowsgui" -o ..\..\check-with-virustotal.exe

echo Done.
pause
