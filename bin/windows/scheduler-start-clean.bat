@echo off
echo.

SETLOCAL ENABLEDELAYEDEXPANSION
call init.bat scheduler-log4j-server
%JAVA_CMD% -Dpa.scheduler.db.hibernate.dropdb=true -Dderby.stream.error.file="%PA_SCHEDULER%\.logs\derby.log" org.ow2.proactive.scheduler.util.SchedulerStarter %*

ENDLOCAL

:end
echo.