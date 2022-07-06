#include "Memory.h"

#include "General.h"
PVOID Memory_Allocate(DWORD uSize)
{
	static NTSTATUS(__stdcall * NtMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID * BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect);
	if (!NtMapViewOfSection) NtMapViewOfSection = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtMapViewOfSection");
}
PVOID Memory_GetCurrentHeap(void) {
	return NtGetPeb()->ProcessHeap;
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
};