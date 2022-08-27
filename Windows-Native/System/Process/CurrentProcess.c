#include "CurrentProcess.h"


BOOL CurrentProcess_DetectDebugger(void)
{

    CONTEXT ctx = { 0 };
    static NTSTATUS(__stdcall* NtGetContextThread)(HANDLE ThreadHandle, PCONTEXT pContext) = NULL;
    if (!NtGetContextThread) NtGetContextThread = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtGetContextThread");
    bool isDebugged = NtGetPeb()->BeingDebugged;
    if (isDebugged) return isDebugged;

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    // Dr6 - debug status
    // Dr7 - debug control
    if (NT_SUCCESS(NtGetContextThread(NtCurrentThread(), &ctx)))
        isDebugged = ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || ctx.Dr6 || ctx.Dr7;
    if (isDebugged) return isDebugged;
    isDebugged = ((PKUSER_SHARED_DATA)0x7FFE0000)->KdDebuggerEnabled;
    //NtQueryInformationProcess() // ProcessDebugPort
    return isDebugged;
}

BOOL CurrentProcess_UnderWine(void)
{
    return NativeLib.Library.GetModuleFunction(L"ntdll.dll", "wine_get_build_id") ?
        true :
    NativeLib.Library.GetModuleFunction(L"ntdll.dll", "wine_get_version") ?
        true :
        false;
}

UINT64 CurrentProcess_GetId(void)
{
    return (UINT64)NtGetPid();
}

struct CurrentProcess CurrentProcess = {
    .GetCurrentId = &CurrentProcess_GetId,
    .DetectDebugger = &CurrentProcess_DetectDebugger
};
