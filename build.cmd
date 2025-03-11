set JAVA_HOME=C:\Programmi\Java\jdk1.7
set WL_HOME=C:\Oracle\Middleware\12.1.3\wlserver
call %WL_HOME%\server\bin\setWLSEnv.cmd
cmd /c "ant all"
pause
