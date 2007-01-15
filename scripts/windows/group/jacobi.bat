@echo off
echo. 
echo --- Jacobi : nodes initialization ---------------------------------------------

rem --- Verifying current directory
SET COMMAND=%0
IF NOT "%COMMAND:~-4%" == ".bat" (
 SET COMMAND=%0.bat
)
 
SET OK=0
FOR /F %%i in ('dir /b') do IF "%%i" == "%COMMAND%" SET OK=1

IF %OK% == 0 (
echo scripts must be started in the same directory as the script.
goto end
)

goto doit

:usage
echo. 
goto end


:doit
SETLOCAL
IF NOT DEFINED PROACTIVE set PROACTIVE=..\..\..\.

call "%PROACTIVE%\scripts\windows\init.bat"

set XMLDESCRIPTOR=..\..\..\descriptors\Matrix.xml
%JAVA_CMD% org.objectweb.proactive.examples.jacobi.Jacobi %XMLDESCRIPTOR%
ENDLOCAL

:end
echo. 
echo ---------------------------------------------------------
