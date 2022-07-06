#pragma once
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001 // NtCreateUserProcess & NtCreateThreadEx
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_LOADER_WORKER 0x00000010 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_SKIP_LOADER_INIT 0x00000020 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 0x00000040 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_INITIAL_THREAD 0x00000080 // ?
extern void NativeInit(void);

struct Memory
{
	PVOID(*Allocate)(DWORD);
	PVOID(*GetCurrentHeap)(void);
	DWORD(*GetCurrentHeaps)(void);

};

struct Process
{
	BOOLEAN(*Create)(const WCHAR*, const WCHAR*);
	DWORD(*Exists)(const WCHAR*);
	NTSTATUS(*Terminate)(HANDLE, NTSTATUS);
};

struct Library
{
	PVOID(*GetModuleFunction)(const WCHAR*, const CHAR*);
	PVOID(*GetFunction)(PVOID, const CHAR*);
	PVOID(*GetModule)(const WCHAR*);
	PVOID(*Load)(const CHAR*);
};

struct nativeLib
{
	BOOLEAN isInitialized;
	struct Process Process;
	struct Library Library;
	struct Memory Memory;
};

extern struct nativeLib NativeLib;