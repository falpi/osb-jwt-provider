set WL_HOME=C:\Oracle\Middleware\12.1.3\wlserver
call %WL_HOME%\server\bin\setWLSEnv.cmd
cd "%~dp0"
cmd /c "ant all.1213"
pause
