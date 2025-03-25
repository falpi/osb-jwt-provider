set WL_HOME=C:\Oracle\Middleware\14.1.2\wlserver
call %WL_HOME%\server\bin\setWLSEnv.cmd
set JDK_JAVA_OPTIONS=%JDK_JAVA_OPTIONS% --add-exports java.xml/com.sun.org.apache.xpath.internal=ALL-UNNAMED --add-exports java.xml/com.sun.org.apache.xpath.internal.objects=ALL-UNNAMED
cd "%~dp0"
cmd /c "ant all.1412"
pause
