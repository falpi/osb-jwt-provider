set WL_HOME=C:\Oracle\Middleware\14.1.2\wlserver
call %WL_HOME%\server\bin\setWLSEnv.cmd
cd "%~dp0"
cmd /c "ant all.1412"
pause
