#include <framework.h>
#include "API.h"

#include <string.h>

EXTERNC IMAGE_DOS_HEADER __ImageBase;
#define HINST_THISCOMPONENT ((HINSTANCE)&__ImageBase)

void* API_GetModule(const WCHAR* dllName)
{
#if defined( _WIN64 )  
#define PEBOffset 0x60  
	PPEB pPeb = (PPEB)__readgsqword(PEBOffset);
#elif defined( _WIN32 )  
#define PEBOffset 0x30  
	PPEB pPeb = (PPEB)__readfsdword(PEBOffset);
#endif
	if (dllName == NULL) return pPeb->ImageBaseAddress;

	PLDR_DATA_TABLE_ENTRY pModuleList = (PLDR_DATA_TABLE_ENTRY*)pPeb->Ldr->InLoadOrderModuleList.Flink;
	//pModuleList = 
	while (pModuleList->DllBase)
	{
		if (!_wcsicmp(pModuleList->BaseDllName.buffer, dllName))
			return pModuleList->DllBase;
		pModuleList = (PLDR_DATA_TABLE_ENTRY)pModuleList->InLoadOrderLinks.Flink;
	}
	return NULL;
}

void* API_GetFunction(PVOID hModule, const char* funcName)
{
	if (!hModule)
	{
		hModule = API_GetModule(0);
	}
	PBYTE pDest = (PBYTE)hModule;
	int idx = -1;
	PIMAGE_DOS_HEADER pImageDosDest = (PIMAGE_DOS_HEADER)pDest;
	PIMAGE_NT_HEADERS pImageNtDest = (PIMAGE_NT_HEADERS)&pDest[pImageDosDest->e_lfanew];
	PIMAGE_DATA_DIRECTORY pDirectory = &pImageNtDest->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	if (pDirectory->Size == 0)
		return NULL;
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((ULONGLONG)pDest + pDirectory->VirtualAddress);

	if (pExport->NumberOfNames == 0 || pExport->NumberOfFunctions == 0)
		return NULL;
	WORD* ordinal = (WORD*)((ULONGLONG)pDest + pExport->AddressOfNameOrdinals);
	if ((DWORD)(funcName) < 0x10000)
	{
		if ((DWORD)funcName >= pExport->NumberOfFunctions + pExport->Base || (DWORD)funcName < pExport->Base)
			return NULL;
		idx = (DWORD)pDest + ((DWORD*)((DWORD)pDest + pExport->AddressOfFunctions))[(DWORD)funcName - pExport->Base];
	}
	else
	{
		DWORD* nameRef = (DWORD*)((ULONGLONG)pDest + pExport->AddressOfNames);
		for (DWORD i = 0; i < pExport->NumberOfNames; i++, nameRef++, ordinal++) {
			if (strcmp(funcName, (const char*)((ULONGLONG)pDest + (*nameRef))) == 0) {
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
	return (void*)((ULONGLONG)hModule + (*(DWORD*)((ULONGLONG)hModule + pExport->AddressOfFunctions + (idx * 4))));
}

void* API_LoadLibrary(const CHAR* dllPath)
{
}


struct API Api = {
	.GetFunction = (void*)API_GetFunction,
	.GetModule = (void*)API_GetModule,
	.LoadLibrary = (void*)API_LoadLibrary,
};