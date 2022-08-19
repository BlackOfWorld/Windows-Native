#pragma once
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001 // NtCreateUserProcess & NtCreateThreadEx
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_LOADER_WORKER 0x00000010 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_SKIP_LOADER_INIT 0x00000020 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 0x00000040 // NtCreateThreadEx only
extern void NativeInit(void);

struct Memory
{
    PVOID(*AllocateHeap)(DWORD uSize, BOOL zeroMem);
    PVOID(*AllocateVirtual)(size_t dwSize, DWORD AllocFlags, DWORD Protect);
    PVOID(*GetCurrentHeap)(void);
    DWORD(*GetCurrentHeaps)(void);
    BOOLEAN(*FreeHeap)(PVOID Address);
    BOOLEAN(*FreeVirtual)(PVOID Address, SIZE_T dwSize, DWORD FreeType);
};

struct CurrentProcess
{
    BOOL(*DetectDebugger)(void);
    UINT64(*GetCurrentId)(void);
};

struct Process
{
    PHANDLE(*Create)(const WCHAR*, const WCHAR*);
    DWORD(*Exists)(const WCHAR* processName);
    NTSTATUS(*Terminate)(HANDLE processHandle, NTSTATUS exitStatus);
    struct CurrentProcess CurrentProcess;
};

struct Library
{
    PVOID(*GetModuleFunction)(const WCHAR* dllName, const CHAR* funcName);
    PVOID(*GetFunctionByOrdinal)(PVOID hModule, DWORD Ordinal);
    PVOID(*GetFunction)(PVOID hModule, const CHAR* funcName);
    PVOID(*GetModule)(const WCHAR* dllName);
    PVOID(*Load)(const CHAR*);
};
struct File
{
    PHANDLE(*Create)(PWCHAR fileName, DWORD Access, DWORD ShareMode, DWORD CreationDisposition, DWORD FlagsAndAttributes);
    INT64(*Size)(HANDLE hFile);
    BOOL(*Close)(HANDLE hFile);
};
struct nativeLib
{
    BOOLEAN isInitialized;
    struct Process Process;
    struct Library Library;
    struct Memory Memory;
    struct File File;
};

extern struct nativeLib NativeLib;