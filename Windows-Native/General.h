#pragma once
extern void NativeInit();

struct Process
{
	BOOLEAN(*Create)(const CHAR*);
	DWORD(*Exists)(const WCHAR*);
};

struct LIBRARY
{
	PVOID(*GetFunction)(PVOID, const CHAR*);
	PVOID(*GetModule)(const WCHAR*);
	PVOID(*Load)(const CHAR*);
};

struct nativeLib
{
	BOOLEAN isInitialized;
	struct Process Process;
	struct LIBRARY Library;
};

extern struct nativeLib NativeLib;