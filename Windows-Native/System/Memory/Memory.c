#include "Memory.h"

#include "General.h"
#define HEAP_NO_SERIALIZE               0x00000001
#define HEAP_GROWABLE                   0x00000002
#define HEAP_GENERATE_EXCEPTIONS        0x00000004
#define HEAP_ZERO_MEMORY                0x00000008
#define HEAP_REALLOC_IN_PLACE_ONLY      0x00000010
#define HEAP_TAIL_CHECKING_ENABLED      0x00000020
#define HEAP_FREE_CHECKING_ENABLED      0x00000040
#define HEAP_DISABLE_COALESCE_ON_FREE   0x00000080
#define HEAP_CREATE_ALIGN_16            0x00010000
#define HEAP_CREATE_ENABLE_TRACING      0x00020000
#define HEAP_CREATE_ENABLE_EXECUTE      0x00040000
#define HEAP_MAXIMUM_TAG                0x0FFF
#define HEAP_PSEUDO_TAG_FLAG            0x8000
#define HEAP_TAG_SHIFT                  18
#define HEAP_CREATE_SEGMENT_HEAP        0x00000100
#define HEAP_CREATE_HARDENED            0x00000200

PVOID Memory_AllocateHeap(DWORD dwSize, BOOL zeroMem)
{
    static PVOID(NTAPI * RtlAllocateHeap)(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
    if (!RtlAllocateHeap) RtlAllocateHeap = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "RtlAllocateHeap");
    return RtlAllocateHeap(Memory.GetCurrentHeap(), zeroMem ? HEAP_ZERO_MEMORY : 0, dwSize);
}

PVOID Memory_AllocateVirtual2(PVOID address, size_t dwSize, DWORD AllocFlags, DWORD Protect)
{
    static NTSTATUS(NTAPI * NtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID * BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
    if (!NtAllocateVirtualMemory) NtAllocateVirtualMemory = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtAllocateVirtualMemory");
    NTSTATUS status = NtAllocateVirtualMemory(NtCurrentProcess(), &address, 0, &dwSize, AllocFlags & 0xFFFFFFC0, Protect);
    SetLastNTError(status);
    if (NT_SUCCESS(status)) return address;
    return NULL;
}

PVOID Memory_AllocateVirtual(size_t dwSize, DWORD AllocFlags, DWORD Protect)
{
    return Memory_AllocateVirtual2(NULL, dwSize, AllocFlags, Protect);
}

PVOID Memory_ReAllocHeap(PVOID Address,DWORD dwSize, BOOL zeroMem)
{
    static PVOID(NTAPI* RtlReAllocateHeap)(PVOID HeapHandle, ULONG Flags, PVOID MemoryPointer, ULONG Size) = NULL;
    if(!RtlReAllocateHeap) RtlReAllocateHeap = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "RtlReAllocateHeap");
    return RtlReAllocateHeap(Memory.GetCurrentHeap(), zeroMem ? HEAP_ZERO_MEMORY : 0, Address, dwSize);
}
BOOLEAN RtlFlushSecureMemoryCache(PVOID MemoryCache, SIZE_T MemoryLength)
{
    static BOOLEAN(NTAPI * RtlFlushSecureMemoryCache)(PVOID MemoryCache, SIZE_T MemoryLength);
    if (!RtlFlushSecureMemoryCache) RtlFlushSecureMemoryCache = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "RtlFlushSecureMemoryCache");
    return RtlFlushSecureMemoryCache(MemoryCache, MemoryLength);
}

BOOLEAN Memory_FreeVirtual(LPVOID Address, SIZE_T dwSize, DWORD FreeType)
{
    if (!dwSize || !(FreeType & MEM_RELEASE))
    {
        SetLastNTError(STATUS_INVALID_PARAMETER);
        return false;
    }
    static NTSTATUS(NTAPI* NtFreeVirtualMemory)(HANDLE ProcessHandle, PVOID * BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
    if (!NtFreeVirtualMemory) NtFreeVirtualMemory = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtFreeVirtualMemory");
    NTSTATUS status = NtFreeVirtualMemory(NtCurrentProcess(), &Address, &dwSize, FreeType);
    if(status == STATUS_INVALID_PAGE_PROTECTION)
    {
        if(!RtlFlushSecureMemoryCache(Address, dwSize))
        {
            SetLastNTError(status);
            return false;
        }
        status = NtFreeVirtualMemory(NtCurrentProcess(), &Address, &dwSize, FreeType);
    }
    SetLastNTError(status);
    if (NT_SUCCESS(status)) return true;
    return false;
}
BOOLEAN Memory_FreeHeap(PVOID Address)
{
    static BOOLEAN(_stdcall * RtlFreeHeap)(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress);
    if (!RtlFreeHeap) RtlFreeHeap = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "RtlFreeHeap");
    return RtlFreeHeap(Memory.GetCurrentHeap(), 0, Address);
}
inline PVOID Memory_GetCurrentHeap(void) {
    //Cache heap
    static PHEAP heap = NULL;
    if (!heap) heap = NtGetPeb()->ProcessHeap;
    return heap;
}
//DWORD Memory_GetCurrentHeaps(void) {
//    static DWORD(NTAPI * GetProcessHeaps)(DWORD NumberOfHeaps, PHANDLE ProcessHeaps);
//    if (!GetProcessHeaps) GetProcessHeaps = NativeLib.Library.GetModuleFunction(L"kernel32.dll", "GetProcessHeaps");
//    DWORD nHeaps = GetProcessHeaps(0, NULL);
//    return GetProcessHeaps(0, NULL);
//}
BOOL Memory_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, LPDWORD lpflOldProtect)
{
    static NTSTATUS(*NTAPI NtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID * BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
    if(!NtProtectVirtualMemory) NtProtectVirtualMemory = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtProtectVirtualMemory");
    NTSTATUS status = NtProtectVirtualMemory(NtCurrentProcess(), lpAddress, dwSize, flNewProtect, lpflOldProtect);
    if (status == STATUS_INVALID_PAGE_PROTECTION)
    {
        if (!RtlFlushSecureMemoryCache(lpAddress, dwSize))
        {
            SetLastNTError(status);
            return false;
        }
        status = NtProtectVirtualMemory(NtCurrentProcess(), lpAddress, dwSize, flNewProtect, lpflOldProtect);
    }
    SetLastNTError(status);
    if (NT_SUCCESS(status)) return true;
    return false;
}
BOOL FlushInstructionCache(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize)
{
    static NTSTATUS(*NTAPI NtFlushInstructionCache)(HANDLE ProcessHandle,PVOID BaseAddress,ULONG NumberOfBytesToFlush);
    if (!NtFlushInstructionCache) NtFlushInstructionCache = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtFlushInstructionCache");
    return NtFlushInstructionCache(hProcess, lpBaseAddress, dwSize);
}


struct Memory Memory = {
    .AllocateHeap = &Memory_AllocateHeap,
    .AllocateVirtual = &Memory_AllocateVirtual,
    .AllocateVirtual2 = &Memory_AllocateVirtual2,
    .ProtectVirtual = &Memory_VirtualProtect,
    .ReAllocHeap = &Memory_ReAllocHeap,
    .GetCurrentHeap = &Memory_GetCurrentHeap,
    //.GetCurrentHeaps = &Memory_GetCurrentHeaps,
    .FreeHeap = &Memory_FreeHeap,
    .FreeVirtual = &Memory_FreeVirtual,
    .FlushInstructionCache = &FlushInstructionCache
};