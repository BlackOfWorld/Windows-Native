#include <framework.h>
#include "Process.h"

#include <string.h>

typedef struct tagPROCESSENTRY32W {
	DWORD     dwSize;
	DWORD     cntUsage;
	DWORD     th32ProcessID;
	ULONG_PTR th32DefaultHeapID;
	DWORD     th32ModuleID;
	DWORD     cntThreads;
	DWORD     th32ParentProcessID;
	LONG      pcPriClassBase;
	DWORD     dwFlags;
	WCHAR     szExeFile[MAX_PATH];
} PROCESSENTRY32W, *LPPROCESSENTRY32W;


BOOLEAN Process_Create(const CHAR* filename)
{
	return false;
}

DWORD Process_Exists(const WCHAR* processName)
{
	typedef BOOL(__stdcall* tProcess32FirstW)(HANDLE, LPPROCESSENTRY32W);
	static tProcess32FirstW Process32FirstW;
	if (!Process32FirstW) Process32FirstW = (tProcess32FirstW)NativeLib.Library.GetFunction(NativeLib.Library.GetModule(L"Kernel32.dll"), "Process32FirstW");
	typedef BOOL(__stdcall* tProcess32NextW)(HANDLE, LPPROCESSENTRY32W);
	static tProcess32NextW Process32NextW;
	if (!Process32NextW) Process32NextW = (tProcess32NextW)NativeLib.Library.GetFunction(NativeLib.Library.GetModule(L"Kernel32.dll"), "Process32NextW");
	typedef HANDLE(__stdcall* tCreateToolhelp32Snapshot)(DWORD, DWORD);
	static tCreateToolhelp32Snapshot CreateToolhelp32Snapshot;
	if(!CreateToolhelp32Snapshot) CreateToolhelp32Snapshot = (tCreateToolhelp32Snapshot)NativeLib.Library.GetFunction(NativeLib.Library.GetModule(L"Kernel32.dll"), "CreateToolhelp32Snapshot");

	HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32W entry;
	entry.dwSize = sizeof(PROCESSENTRY32W);
	Process32FirstW(handle, &entry);
	do
	{
		if (!_wcsicmp(processName, entry.szExeFile))
			return entry.th32ProcessID;
	} while (Process32NextW(handle, &entry));
	return 0;
} 

struct Process Process = {
	.Create = &Process_Create,
	.Exists = &Process_Exists,
};