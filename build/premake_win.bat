@echo off
set "arg=%~1"

rem Custom clean function, because premake doesn't support clean yet
if "%arg%"=="clean" (rmdir /s /q ..\out & exit /b 0)

rem Default argument is vs2022
if "%arg%"=="" (set "arg=vs2022")

bin\win\premake5 --file=..\premake5.lua %arg%
@echo on