// NativeLib.cpp : Defines the functions for the static library.
//

#include "framework.h"
#include "General.h"

#include "Native/API/Library.h"
#include "System/Process/Process.h"
#include "System/Memory/Memory.h"
#include "System/Filesystem/File.h"
#include "System/Process/CurrentProcess.h"

struct nativeLib NativeLib;
NTSTATUS(NTAPI* NtWaitForSingleObject)(HANDLE hObject, BOOLEAN bAlertable, PLARGE_INTEGER Timeout);


NTSTATUS NTAPI NtClose(HANDLE Handle)
{
    static NTSTATUS(NTAPI * _imp_NtClose)(HANDLE Handle);
    static NTSTATUS(NTAPI* NtQueryObject)(HANDLE ObjectHandle, OBJECT_INFORMATION_CLASS ObjectInformationClass,PVOID ObjectInformation,ULONG Length,PULONG ResultLength);
    if(!NtQueryObject) NtQueryObject = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtQueryObject");
    if(!_imp_NtClose) _imp_NtClose = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtClose");
    OBJECT_ATTRIBUTES objAttr;
    NTSTATUS status = NtQueryObject(Handle, ObjectNameInformation, &objAttr, 2, 0);
    assert(status != STATUS_INVALID_HANDLE, "Invalid handle!");
    return _imp_NtClose(Handle);
}

EXTERNC void NativeInit()
{
    if (NativeLib.isInitialized) return;
    NativeLib.isInitialized = true;
    NativeLib.Process = Process;
    NativeLib.Process.CurrentProcess = CurrentProcess;
    NativeLib.Library = Library;
    NativeLib.Memory = Memory;
    NativeLib.File = File;
    cpu_detect_features();
    NtWaitForSingleObject = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtWaitForSingleObject");
}