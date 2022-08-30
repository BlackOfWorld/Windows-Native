#pragma once
#include "framework.h"
#include "General.h"
#define GetConsoleHandle() NtGetPeb()->ProcessParameters->ConsoleHandle
extern VOID WriteConsole(HANDLE hConsoleOutput, PVOID lpBuffer, DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten);
