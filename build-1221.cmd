set WL_HOME=C:\Oracle\Middleware\12.2.1\wlserver
call %WL_HOME%\server\bin\setWLSEnv.cmd
cd "%~dp0"
cmd /c "ant all.1221"
pause
