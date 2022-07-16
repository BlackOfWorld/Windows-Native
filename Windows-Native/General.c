// NativeLib.cpp : Defines the functions for the static library.
//

#include "framework.h"
#include "General.h"

#include "Native/API/Library.h"
#include "System/Process/Process.h"
#include "Memory/Memory.h"
#include "System/File/File.h"

struct nativeLib NativeLib;
NTSTATUS(__stdcall* NtClose)(HANDLE Handle);
EXTERNC void NativeInit()
{
	if (NativeLib.isInitialized) return;
	NativeLib.isInitialized = true;
	NativeLib.Process = Process;
	NativeLib.Library = Library;
	NativeLib.Memory = Memory;
	NativeLib.File = File;
	cpu_detect_features();
	NtClose = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtClose");
}