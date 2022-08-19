#pragma once
#include <framework.h>
#include <General.h>

typedef struct _RTLP_CURDIR_REF
{
    LONG ReferenceCount;
    HANDLE DirectoryHandle;
} RTLP_CURDIR_REF, * PRTLP_CURDIR_REF;

typedef struct _RTL_RELATIVE_NAME_U
{
    UNICODE_STRING RelativeName;
    HANDLE ContainingDirectory;
    PRTLP_CURDIR_REF CurDirRef;
} RTL_RELATIVE_NAME_U, * PRTL_RELATIVE_NAME_U;
struct Path
{
    NTSTATUS(*RtlDosSearchPath_Ustr)(ULONG Flags, PUNICODE_STRING PathString, PUNICODE_STRING FileNameString, PUNICODE_STRING ExtensionString, PUNICODE_STRING CallerBuffer, PUNICODE_STRING DynamicString, PUNICODE_STRING* FullNameOut, PSIZE_T FilePartSize, PSIZE_T LengthNeeded);
    NTSTATUS(*RtlDosPathNameToNtPathName_U)(PCWSTR DosFileName, PUNICODE_STRING NtFileName, PWSTR* FilePart, PRTL_RELATIVE_NAME_U RelativeName);
    NTSTATUS(*RtlGetExePath)(PCWSTR name, PWSTR* path);
    DWORD(*SearchPathW)(LPCWSTR lpPath, LPCWSTR lpFileName, LPCWSTR lpExtension, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR* lpFilePart);
    NTSTATUS(*RtlGetSearchPath)(PWCHAR* SearchPath);
};

extern struct Path Path;