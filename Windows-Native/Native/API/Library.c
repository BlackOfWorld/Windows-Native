#include <framework.h>
#include "Library.h"

#include <string.h>

#include "Loader.h"

EXTERNC IMAGE_DOS_HEADER __ImageBase;
#define HINST_THISCOMPONENT ((HINSTANCE)&__ImageBase)

void* Library_GetModule(const WCHAR* dllName)
{
#if defined(_WIN64)
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif defined(_WIN32)
	PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
	if (dllName == NULL) return pPeb->ImageBaseAddress;

	//PLDR_DATA_TABLE_ENTRY pModuleList = (PLDR_DATA_TABLE_ENTRY*)->InLoadOrderModuleList.Flink;
	//pModuleList =
	PPEB_LDR_DATA pLdr = pPeb->Ldr;
	for (PLIST_ENTRY list = pLdr->InLoadOrderModuleList.Flink; list != &pLdr->InLoadOrderModuleList; list = list->Flink) {
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (!_wcsicmp(pEntry->BaseDllName.Buffer, dllName))
			return pEntry->DllBase;
	}
	return NULL;
}

void* Library_GetFunction(PVOID hModule, const char* funcName)
{
	if (!hModule)
	{
		hModule = Library_GetModule(0);
	}
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
	if ((DWORD)(funcName) < 0x10000)
	{
		if ((DWORD)funcName >= pExport->NumberOfFunctions + pExport->Base || (DWORD)funcName < pExport->Base)
			return NULL;
		idx = (size_t)pDest + ((DWORD*)((size_t)pDest + pExport->AddressOfFunctions))[(DWORD)funcName - pExport->Base];
	}
	else
	{
		DWORD* nameRef = (DWORD*)((size_t)pDest + pExport->AddressOfNames);
		for (DWORD i = 0; i < pExport->NumberOfNames; i++, nameRef++, ordinal++) {
			if (strcmp(funcName, (const char*)((size_t)pDest + (*nameRef))) == 0) {
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
	return (void*)((size_t)hModule + (*(DWORD*)((size_t)hModule + pExport->AddressOfFunctions + (idx * 4))));
}


void* Library_Load(DWORD flags, const wchar_t* dllName, PBYTE buffer, size_t bufferLen)
{
	struct Loader_Module mod;
	switch(LOWORD(flags))
	{
	case File:

		break;
	case Memory:
		mod.data = buffer;
		mod.dataLen = bufferLen;
		mod.cDllName = mod.dllName = dllName;
		break;
	}

	return NULL;
}


struct LIBRARY Library = {
	.GetFunction = (void*)Library_GetFunction,
	.GetModule = (void*)Library_GetModule,
	.Load = (void*)Library_Load,
};