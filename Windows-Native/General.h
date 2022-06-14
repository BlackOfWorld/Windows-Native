#pragma once
extern void NativeInit();

struct Process
{
	BOOLEAN(*Create)(const CHAR*);
	DWORD(*Exists)(const WCHAR*);
};

struct API
{
	PVOID(*GetFunction)(PVOID, const CHAR*);
	PVOID(*GetModule)(const WCHAR*);
	PVOID(*LoadLibrary)(const CHAR*);
};

struct nativeLib
{
	BOOLEAN isInitialized;
	struct Process Process;
	struct API Api;
};

extern struct nativeLib NativeLib;