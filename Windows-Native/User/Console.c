#include "Console.h"

#define GetConsoleHandle() NtGetPeb()->ProcessParameters->ConsoleHandle
// Read console 0x1000005
VOID WriteConsole(HANDLE hConsoleOutput, PVOID lpBuffer, DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten)
{
    NativeLib.File.Write(hConsoleOutput, lpBuffer, nNumberOfCharsToWrite, lpNumberOfCharsWritten, NULL);
}