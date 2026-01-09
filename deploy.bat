@echo off
net stop AuthUnlockerService
taskkill /f /im AuthUnlocker.Monitor.exe
taskkill /f /im AuthUnlocker.Service.exe
timeout /t 2
net start AuthUnlockerService
