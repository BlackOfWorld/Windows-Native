#include <framework.h>
#include "Library.h"

#include "Loader.h"
#include "Memory/Memory.h"

EXTERNC IMAGE_DOS_HEADER __ImageBase;
#define HINST_THISCOMPONENT ((HINSTANCE)&__ImageBase)

void* Library_GetModule(const WCHAR* dllName)
{
	PPEB pPeb = NtGetPeb();
	if (!dllName || !dllName[0]) return pPeb->ImageBaseAddress;
	PPEB_LDR_DATA pLdr = pPeb->Ldr;
	for (PLIST_ENTRY list = pLdr->InLoadOrderModuleList.Flink; list != &pLdr->InLoadOrderModuleList; list = list->Flink) {
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (!wcsnicmp(pEntry->BaseDllName.Buffer, dllName, pEntry->BaseDllName.Length / sizeof(wchar_t) - 4))
			return pEntry->DllBase;
	}
	return NULL;
}
PVOID Library_GetModuleFunction(const WCHAR* dllName, const char* funcName);
PVOID HandleForwardedFunction(PVOID hModule, ULONG_PTR pFuncAddr)
{
	char* strAddr = (char*)(ULONG_PTR)hModule + pFuncAddr;
	char libA[MAX_PATH] = { 0 };
	wchar_t libW[MAX_PATH] = { 0 };
	char funcA[MAX_PATH] = { 0 };
	char* dot = (char*)strchrA(strAddr, '.');
	if (dot == 0) __debugbreak();
	size_t dotI = dot - strAddr;
	memcpy(libA, strAddr, dotI);
	memcpy(funcA, ++dot, strlenA(dot));
	mbstowcs(libW, libA, dotI);
	return Library.GetModuleFunction(libW, funcA);
}
void* Library_GetFunctionByOrdinal(PVOID hModule, DWORD Ordinal)
{
	if (!hModule) hModule = Library_GetModule(0);
	const PBYTE pDest = hModule;
	PIMAGE_DOS_HEADER pImageDosDest = (PIMAGE_DOS_HEADER)pDest;
	PIMAGE_NT_HEADERS pImageNtDest = (PIMAGE_NT_HEADERS)&pDest[pImageDosDest->e_lfanew];
	PIMAGE_DATA_DIRECTORY pDirectory = &pImageNtDest->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	if (pDirectory->Size == 0)
		return NULL;
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((ULONGLONG)pDest + pDirectory->VirtualAddress);

	if (pExport->NumberOfNames == 0 || pExport->NumberOfFunctions == 0)
		return NULL;
	if (Ordinal > pExport->NumberOfFunctions) {
		return NULL;
	}
	ULONG_PTR pFuncAddr = *(DWORD*)((ULONG_PTR)hModule + pExport->AddressOfFunctions + Ordinal * 4);
	if (pFuncAddr >= pDirectory->VirtualAddress && pFuncAddr < pDirectory->VirtualAddress + pDirectory->Size)
	{
		return HandleForwardedFunction(hModule, pFuncAddr);
	}

	return (void*)((ULONG_PTR)hModule + pFuncAddr);
}
void* Library_GetFunction(PVOID hModule, const char* funcName)
{
	if (!hModule) hModule = Library_GetModule(0);
	const PBYTE pDest = hModule;
	int idx = -1;
	PIMAGE_DOS_HEADER pImageDosDest = (PIMAGE_DOS_HEADER)pDest;
	PIMAGE_NT_HEADERS pImageNtDest = (PIMAGE_NT_HEADERS)&pDest[pImageDosDest->e_lfanew];
	PIMAGE_DATA_DIRECTORY pDirectory = &pImageNtDest->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	if (pDirectory->Size == 0)
		return NULL;
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((ULONGLONG)pDest + pDirectory->VirtualAddress);

	if (pExport->NumberOfNames == 0 || pExport->NumberOfFunctions == 0)
		return NULL;
	WORD* ordinal = (WORD*)((size_t)pDest + pExport->AddressOfNameOrdinals);
	if ((DWORD)funcName < 0x10000)
	{
		if ((DWORD)funcName >= pExport->NumberOfFunctions + pExport->Base || (DWORD)funcName < pExport->Base)
			return NULL;
		idx = (size_t)pDest + ((DWORD*)((size_t)pDest + pExport->AddressOfFunctions))[(DWORD)funcName - pExport->Base];
	}
	else
	{
		DWORD* nameRef = (DWORD*)((size_t)pDest + pExport->AddressOfNames);
		for (DWORD i = 0; i < pExport->NumberOfNames; i++, nameRef++, ordinal++) {
			if (strcmpA(funcName, (const char*)((size_t)pDest + (*nameRef))) == 0) {
				idx = *ordinal;
				break;
			}
		}
	}
	if (idx == -1) {
		return NULL;
	}
	if ((DWORD)idx > pExport->NumberOfFunctions) {
		return NULL;
	}
	ULONG_PTR pFuncAddr = *(DWORD*)((ULONG_PTR)hModule + pExport->AddressOfFunctions + idx * 4);
	if (pFuncAddr >= pDirectory->VirtualAddress && pFuncAddr < pDirectory->VirtualAddress + pDirectory->Size)
	{
		return HandleForwardedFunction(hModule, pFuncAddr);
	}

	return (void*)((ULONG_PTR)hModule + pFuncAddr);
}

PVOID Library_GetModuleFunction(const WCHAR* dllName, const char* funcName)
{
	const PVOID mod = Library.GetModule(dllName);
	return funcName == NULL ||
		mod == NULL ?
		NULL : Library.GetFunction(mod, funcName);
}

void* Library_Load(struct MemoryLoad memLoad)
{
	struct Loader_Module mod;
	switch(memLoad.flags)
	{
	case LoadFile:
		break;
	case LoadMemory:
		mod.data = memLoad.buffer;
		mod.dataLen = memLoad.bufferLen;
		mod.cDllName = mod.dllName = memLoad.dllName;
		break;
	default:
		__debugbreak();
	}

	return NULL;
}

struct Library Library = {
	.GetFunction = &Library_GetFunction,
	.GetFunctionByOrdinal = &Library_GetFunctionByOrdinal,
	.GetModuleFunction = &Library_GetModuleFunction,
	.GetModule = &Library_GetModule,
	.Load = &Library_Load,
};
