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

PVOID Memory_Allocate(DWORD uSize, BOOL zeroMem)
{
	//static NTSTATUS(__stdcall * NtMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID * BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect);
	//if (!NtMapViewOfSection) NtMapViewOfSection = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtMapViewOfSection");
	//NtMapViewOfSection()
	static PVOID(_stdcall * RtlAllocateHeap)(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
	if (!RtlAllocateHeap) RtlAllocateHeap = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "RtlAllocateHeap");
	return RtlAllocateHeap(Memory.GetCurrentHeap(), zeroMem ? HEAP_ZERO_MEMORY : 0, uSize);
}
BOOLEAN Memory_FreeHeap(PVOID Address)
{
	static BOOLEAN(_stdcall * RtlFreeHeap)(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress);
	if (!RtlFreeHeap) RtlFreeHeap = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "RtlFreeHeap");
	return RtlFreeHeap(Memory.GetCurrentHeap(), 0, Address);
}
inline PVOID Memory_GetCurrentHeap(void) {
	//Cache heap
	static PVOID heap = NULL;
	if (!heap) heap = NtGetPeb()->ProcessHeap;
	return heap;
}
DWORD Memory_GetCurrentHeaps(void) {
	static DWORD(__stdcall * GetProcessHeaps)(DWORD NumberOfHeaps, PHANDLE ProcessHeaps);
	if (!GetProcessHeaps) GetProcessHeaps = NativeLib.Library.GetModuleFunction(L"kernel32.dll", "GetProcessHeaps");
	DWORD nHeaps = GetProcessHeaps(0, NULL);
	return GetProcessHeaps(0, NULL);
}


struct Memory Memory = {
	.Allocate = &Memory_Allocate,
	.GetCurrentHeap = &Memory_GetCurrentHeap,
	.GetCurrentHeaps = &Memory_GetCurrentHeaps,
	.Free = &Memory_FreeHeap
};