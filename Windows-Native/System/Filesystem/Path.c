#include "Path.h"


#ifdef _WIN64
#define NTCALL __fastcall
#else
#define NTCALL __stdcall
#endif

//THIS FUCKS UP THE STACK!!
NTSTATUS RtlDosSearchPath_Ustr(ULONG Flags, PUNICODE_STRING PathString, PUNICODE_STRING FileNameString, PUNICODE_STRING ExtensionString, PUNICODE_STRING CallerBuffer, PUNICODE_STRING DynamicString, PUNICODE_STRING* FullNameOut, PSIZE_T FilePartSize, PSIZE_T LengthNeeded)
{
    static NTSTATUS(NTCALL* RtlDosSearchPath_Ustr)(ULONG Flags, PUNICODE_STRING PathString, PUNICODE_STRING FileNameString, PUNICODE_STRING ExtensionString, PUNICODE_STRING CallerBuffer, PUNICODE_STRING DynamicString, PUNICODE_STRING * FullNameOut, PSIZE_T FilePartSize, PSIZE_T LengthNeeded) = NULL;
    if (!RtlDosSearchPath_Ustr) RtlDosSearchPath_Ustr = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "RtlDosSearchPath_Ustr");
    return RtlDosSearchPath_Ustr(Flags, PathString, FileNameString, ExtensionString, CallerBuffer, DynamicString, FullNameOut, FilePartSize, LengthNeeded);
}
NTSTATUS RtlDosPathNameToNtPathName_U(PCWSTR DosName, PUNICODE_STRING NtName, PWSTR* PartName, PRTL_RELATIVE_NAME_U RelativeName)
{
    static NTSTATUS(NTCALL* RtlpDosPathNameToRelativeNtPathName_Ustr)(PCWSTR DosFileName, PUNICODE_STRING NtFileName, PWSTR * FilePart, PRTL_RELATIVE_NAME_U RelativeName);
    if (!RtlpDosPathNameToRelativeNtPathName_Ustr) RtlpDosPathNameToRelativeNtPathName_Ustr = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "RtlDosLongPathNameToNtPathName_U_WithStatus");
    return RtlpDosPathNameToRelativeNtPathName_Ustr(DosName, NtName, PartName, RelativeName);
}
NTSTATUS RtlGetExePath(PCWSTR name, PWSTR* path)
{
    static NTSTATUS(NTCALL* RtlGetExePath)(PCWSTR name, PWSTR * path) = NULL;
    if (!RtlGetExePath) RtlGetExePath = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "RtlGetExePath");
    return RtlGetExePath(name, path);
}
NTSTATUS RtlGetSearchPath(PWCHAR* SearchPath)
{
    static NTSTATUS(NTCALL* RtlGetSearchPath)(PWCHAR* SearchPath) = NULL;
    if (!RtlGetSearchPath) RtlGetSearchPath = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "RtlGetSearchPath");
    return RtlGetSearchPath(SearchPath);
}
DWORD SearchPathW(LPCWSTR lpPath, LPCWSTR lpFileName, LPCWSTR lpExtension, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR* lpFilePart)
{
    UNICODE_STRING FileNameString, ExtensionString, PathString, CallerBuffer;

    SIZE_T LengthNeeded, FilePartSize;
    SIZE_T Result = 0;

    /* Default flags for RtlDosSearchPath_Ustr */
    ULONG Flags = 6;

    /* Clear file part in case we fail */
    if (lpFilePart) *lpFilePart = NULL;

    /* Initialize path buffer for free later */
    PathString.Buffer = NULL;

    /* Convert filename to a unicode string and eliminate trailing spaces */
    RtlInitUnicodeStringEx(&FileNameString, lpFileName);
    while (FileNameString.Length >= sizeof(WCHAR) &&
        FileNameString.Buffer[FileNameString.Length / sizeof(WCHAR) - 1] == L' ')
    {
        FileNameString.Length -= sizeof(WCHAR);
    }

    /* Was it all just spaces? */
    if (!FileNameString.Length)
    {
        /* Fail out */
        SetLastNTError(STATUS_INVALID_PARAMETER);
        return Result;
    }

    /* Convert extension to a unicode string */
    RtlInitUnicodeStringEx(&ExtensionString, lpExtension);

    RtlGetSearchPath(&PathString.Buffer);
    /* See how big the computed path is */
    LengthNeeded = strlenW(PathString.Buffer);
    if (LengthNeeded > UNICODE_STRING_MAX_CHARS)
    {
        /* Fail if it's too long */
        SetLastNTError(STATUS_NAME_TOO_LONG);
        return Result;
    }

    /* Set the path size now that we have it */
    PathString.MaximumLength = PathString.Length = (USHORT)LengthNeeded * sizeof(WCHAR);

    /* Request SxS isolation from RtlDosSearchPath_Ustr */
    Flags |= 1;

    /* Create the string that describes the output buffer from the caller */
    CallerBuffer.Length = 0;
    CallerBuffer.Buffer = lpBuffer;

    /* How much space does the caller have? */
    if (nBufferLength <= UNICODE_STRING_MAX_CHARS)
    {
        /* Add it into the string */
        CallerBuffer.MaximumLength = (USHORT)nBufferLength * sizeof(WCHAR);
    }
    else
    {
        /* Caller wants too much, limit it to the maximum length of a string */
        CallerBuffer.MaximumLength = UNICODE_STRING_MAX_BYTES;
    }

    /* Call Rtl to do the work */
    NTSTATUS status = RtlDosSearchPath_Ustr(Flags,
        &PathString,
        &FileNameString,
        &ExtensionString,
        &CallerBuffer,
        NULL,
        NULL,
        &FilePartSize,
        &LengthNeeded);
    if (NT_ERROR(status))
    {
        /* Check for unusual status codes */
        if (status != STATUS_NO_SUCH_FILE && status != STATUS_BUFFER_TOO_SMALL)
        {
            __debugbreak();
            ///* Print them out since maybe an app needs fixing */
            //DbgPrint("%s on file %wZ failed; NTSTATUS = %08lx\n",
            //    __FUNCTION__,
            //    &FileNameString,
            //    Status);
            //DbgPrint("    Path = %wZ\n", &PathString);
        }

        /* Check if the failure was due to a small buffer */
        if (status == STATUS_BUFFER_TOO_SMALL)
        {
            /* Check if the length was actually too big for Rtl to work with */
            Result = LengthNeeded / sizeof(WCHAR);
            if (Result > 0xFFFFFFFF) SetLastNTError(STATUS_NAME_TOO_LONG);
        }
        else
        {
            /* Some other error, set the error code */
            SetLastNTError(status);
        }
    }
    else
    {
        /* It worked! Write the file part now */
        if (lpFilePart) *lpFilePart = &lpBuffer[FilePartSize];

        /* Convert the final result length */
        Result = CallerBuffer.Length / sizeof(WCHAR);
    }
    /* Return the final result length */
    return Result;
}
struct Path Path = {
    .RtlDosPathNameToNtPathName_U = RtlDosPathNameToNtPathName_U,
    .RtlDosSearchPath_Ustr = RtlDosSearchPath_Ustr,
    .RtlGetExePath = RtlGetExePath,
    .SearchPathW = SearchPathW,
    .RtlGetSearchPath = RtlGetSearchPath
};