#include "File.h"

#include "Path.h"

#define OBJ_CASE_INSENSITIVE   0x00000040L


typedef void (IO_APC_ROUTINE)(void* ApcContext, IO_STATUS_BLOCK* IoStatusBlock, unsigned long reserved);
static NTSTATUS(NTAPI* NtQueryInformationFile)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) = NULL;

HANDLE File_Create(LPCWSTR fileName, DWORD Access, DWORD ShareMode, DWORD CreationDisposition, DWORD FlagsAndAttributes)
{
    static NTSTATUS(NTAPI * NtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
    if (!NtCreateFile) NtCreateFile = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtCreateFile");
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    UNICODE_STRING NtPathU;
    HANDLE FileHandle;
    ULONG Flags = 0;
    if (!fileName || !fileName[0])
    {
        SetLastNTStatus(STATUS_INVALID_PARAMETER);
        SetLastError(ERROR_PATH_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    switch (CreationDisposition)
    {
    case CREATE_NEW:
        CreationDisposition = FILE_CREATE;
        break;
    case CREATE_ALWAYS:
        CreationDisposition = FILE_OVERWRITE_IF;
        break;
    case OPEN_EXISTING:
        CreationDisposition = FILE_OPEN;
        break;
    case OPEN_ALWAYS:
        CreationDisposition = FILE_OPEN_IF;
        break;
    case TRUNCATE_EXISTING:
        CreationDisposition = FILE_OVERWRITE;
        break;
    default:
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }
    if (!(FlagsAndAttributes & FILE_FLAG_OVERLAPPED))
    {
        /* yes, nonalert is correct! apc's are not delivered
        while waiting for file io to complete */
        Flags |= FILE_SYNCHRONOUS_IO_NONALERT;
    }

    if (FlagsAndAttributes & FILE_FLAG_WRITE_THROUGH)
        Flags |= FILE_WRITE_THROUGH;

    if (FlagsAndAttributes & FILE_FLAG_NO_BUFFERING)
        Flags |= FILE_NO_INTERMEDIATE_BUFFERING;

    if (FlagsAndAttributes & FILE_FLAG_RANDOM_ACCESS)
        Flags |= FILE_RANDOM_ACCESS;

    if (FlagsAndAttributes & FILE_FLAG_SEQUENTIAL_SCAN)
        Flags |= FILE_SEQUENTIAL_ONLY;

    if (FlagsAndAttributes & FILE_FLAG_DELETE_ON_CLOSE)
    {
        Flags |= FILE_DELETE_ON_CLOSE;
        FlagsAndAttributes |= DELETE;
    }

    if (FlagsAndAttributes & FILE_FLAG_BACKUP_SEMANTICS)
    {
        if (FlagsAndAttributes & GENERIC_ALL)
            Flags |= FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REMOTE_INSTANCE;
        else
        {
            if (FlagsAndAttributes & GENERIC_READ)
                Flags |= FILE_OPEN_FOR_BACKUP_INTENT;

            if (FlagsAndAttributes & GENERIC_WRITE)
                Flags |= FILE_OPEN_REMOTE_INSTANCE;
        }
    }
    else
        Flags |= FILE_NON_DIRECTORY_FILE;

    if (FlagsAndAttributes & FILE_FLAG_OPEN_REPARSE_POINT)
        Flags |= FILE_OPEN_REPARSE_POINT;

    if (FlagsAndAttributes & FILE_FLAG_OPEN_NO_RECALL)
        Flags |= FILE_OPEN_NO_RECALL;

    ULONG FileAttributes = FlagsAndAttributes & (FILE_ATTRIBUTE_VALID_FLAGS & ~FILE_ATTRIBUTE_DIRECTORY);

    /* handle may always be waited on and querying attributes are always allowed */
    FlagsAndAttributes |= SYNCHRONIZE | FILE_READ_ATTRIBUTES;

    //TODO: Validate and translate from DOS Path to NT Path internally and don't use ntdll
    if (NT_ERROR(Path.RtlDosPathNameToNtPathName_U(fileName, &NtPathU, NULL, NULL)))
    {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    BOOLEAN TrailingBackslash = NtPathU.Length >= sizeof(WCHAR) && NtPathU.Buffer[NtPathU.Length / sizeof(WCHAR) - 1];
    InitializeObjectAttributes(&ObjectAttributes, &NtPathU, !(FlagsAndAttributes & FILE_FLAG_POSIX_SEMANTICS) ? OBJ_CASE_INSENSITIVE : 0, NULL, NULL);
    NTSTATUS status = NtCreateFile(&FileHandle, Access, &ObjectAttributes, &IoStatusBlock, NULL, FileAttributes, ShareMode, CreationDisposition, Flags, NULL, 0);
    NativeLib.Memory.FreeHeap(NtPathU.Buffer);
    if (NT_ERROR(status))
    {
        if (status == STATUS_OBJECT_NAME_COLLISION && CreationDisposition == FILE_CREATE)
            SetLastError(ERROR_FILE_EXISTS);
        else if (status == STATUS_FILE_IS_A_DIRECTORY && TrailingBackslash)
            SetLastError(ERROR_PATH_NOT_FOUND);
        else
            SetLastNTError(status);
        return INVALID_HANDLE_VALUE;
    }
    if (CreationDisposition == FILE_OPEN_IF)
        SetLastError(IoStatusBlock.Information == FILE_OPENED ? ERROR_ALREADY_EXISTS : ERROR_SUCCESS);
    else if (CreationDisposition == FILE_OVERWRITE_IF)
        SetLastError(IoStatusBlock.Information == FILE_OVERWRITTEN ? ERROR_ALREADY_EXISTS : ERROR_SUCCESS);
    else
        SetLastError(ERROR_SUCCESS);

    return FileHandle;
}
BOOLEAN File_Write(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, PLONGLONG lpNumberOfBytesWritten, PVOID lpOverlapped)
{
    LPOVERLAPPED overlapped = lpOverlapped;
    static NTSTATUS(NTAPI * NtWriteFile)(HANDLE FileHandle, HANDLE Event, IO_APC_ROUTINE * ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
    if (!NtWriteFile) NtWriteFile = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtWriteFile");

    switch ((size_t)hFile)
    {
    case STD_ERROR_HANDLE:
        hFile = NtGetPeb()->ProcessParameters->StandardError;
        break;
    case STD_OUTPUT_HANDLE:
        hFile = NtGetPeb()->ProcessParameters->StandardOutput;
        break;
    case STD_INPUT_HANDLE:
        hFile = NtGetPeb()->ProcessParameters->StandardInput;
        break;
    default: break;
    }

    if (overlapped != NULL)
    {
        LARGE_INTEGER offset =
        {
            .LowPart = overlapped->Offset,
            .HighPart = (LONG)overlapped->OffsetHigh
        };

        overlapped->Internal = STATUS_PENDING;
        PVOID apcContext = (ULONG_PTR)overlapped->hEvent & 0x1 ? NULL : overlapped;

        NTSTATUS status = NtWriteFile(hFile,
            overlapped->hEvent,
            NULL,
            apcContext,
            (PIO_STATUS_BLOCK)overlapped,
            (PVOID)lpBuffer,
            nNumberOfBytesToWrite,
            &offset,
            NULL);

        if (!NT_SUCCESS(status) || status == STATUS_PENDING)
        {
            SetLastNTError(status);
            return FALSE;
        }

        if (lpNumberOfBytesWritten)
            *lpNumberOfBytesWritten = overlapped->InternalHigh;
    }
    else
    {
        IO_STATUS_BLOCK ioStatusBlock;

        NTSTATUS status = NtWriteFile(hFile,
            NULL,
            NULL,
            NULL,
            &ioStatusBlock,
            (PVOID)lpBuffer,
            nNumberOfBytesToWrite,
            NULL,
            NULL);

        SetLastNTError(status);

        /* Wait in case operation is pending */
        if (status == STATUS_PENDING)
        {
            status = NtWaitForSingleObject(hFile, FALSE, NULL);
            if (NT_SUCCESS(status)) status = ioStatusBlock.Status;
        }

        if (NT_SUCCESS(status))
        {

            // Fun fact, in Windows it would normally crash here :P
            if (lpNumberOfBytesWritten)
                *lpNumberOfBytesWritten = ioStatusBlock.Information;
        }
        else return FALSE;

        return TRUE;
    }
    return TRUE;
}
BOOLEAN File_Read(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED overlapped)
{
    NTSTATUS status;
    static NTSTATUS(NTAPI* NtReadFile)(HANDLE FileHandle, HANDLE Event, IO_APC_ROUTINE* ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
    if(!NtReadFile) NtReadFile = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtReadFile");
    if (lpNumberOfBytesRead != NULL)
        *lpNumberOfBytesRead = 0;

    switch ((size_t)hFile)
    {
    case STD_ERROR_HANDLE:
        hFile = NtGetPeb()->ProcessParameters->StandardError;
        break;
    case STD_OUTPUT_HANDLE:
        hFile = NtGetPeb()->ProcessParameters->StandardOutput;
        break;
    case STD_INPUT_HANDLE:
        hFile = NtGetPeb()->ProcessParameters->StandardInput;
        break;
    default: break;
    }

#if 0
    hFile = TranslateStdHandle(hFile);
    if (IsConsoleHandle(hFile))
    {
        if (ReadConsoleA(hFile,
            lpBuffer,
            nNumberOfBytesToRead,
            lpNumberOfBytesRead,
            NULL))
        {
            DWORD dwMode;
            GetConsoleMode(hFile, &dwMode);
            if ((dwMode & ENABLE_PROCESSED_INPUT) && *(PCHAR)lpBuffer == 0x1a)
            {
                /* EOF character entered; simulate end-of-file */
                *lpNumberOfBytesRead = 0;
            }
            return TRUE;
        }
        return FALSE;
    }
#endif
    if (overlapped != NULL)
    {
        LARGE_INTEGER offset =
        {
            .LowPart = overlapped->Offset,
            .HighPart = (LONG)overlapped->OffsetHigh
        };
        overlapped->Internal = STATUS_PENDING;
        PVOID ApcContext = (((ULONG_PTR)overlapped->hEvent & 0x1) ? NULL : overlapped);
        status = NtReadFile(hFile,
            overlapped->hEvent,
            NULL,
            ApcContext,
            (PIO_STATUS_BLOCK)overlapped,
            lpBuffer,
            nNumberOfBytesToRead,
            &offset,
            NULL);
        SetLastNTError(status);
        if (!NT_SUCCESS(status) || status == STATUS_PENDING)
        {
            if (status == STATUS_END_OF_FILE && lpNumberOfBytesRead != NULL)
                *lpNumberOfBytesRead = 0;
            return FALSE;
        }
        if (lpNumberOfBytesRead != NULL)
            *lpNumberOfBytesRead = overlapped->InternalHigh;
    }
    else
    {
        IO_STATUS_BLOCK ioStatusBlock;
        status = NtReadFile(hFile,
            NULL,
            NULL,
            NULL,
            &ioStatusBlock,
            lpBuffer,
            nNumberOfBytesToRead,
            NULL,
            NULL);
        SetLastNTError(status);

        /* Wait in case operation is pending */
        if (status == STATUS_PENDING)
        {
            status = NtWaitForSingleObject(hFile, FALSE, NULL);
            if (NT_SUCCESS(status)) status = ioStatusBlock.Status;
        }
        if (status == STATUS_END_OF_FILE)
        {
            // Here's another fun fact, where Windows would normally crash here :P
            if (lpNumberOfBytesRead) *lpNumberOfBytesRead = 0;
            return TRUE;
        }
        if (NT_SUCCESS(status))
        {
            // Here's another...
            if (lpNumberOfBytesRead) *lpNumberOfBytesRead = ioStatusBlock.Information;
            return TRUE;
        }
        return FALSE;
    }
    return TRUE;
}
UINT64 File_GetSize(HANDLE hFile)
{
    if (!NtQueryInformationFile) NtQueryInformationFile = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtQueryInformationFile");
    FILE_STANDARD_INFORMATION FileStandard = { 0 };
    IO_STATUS_BLOCK IoStatusBlock = { 0 };

    NTSTATUS errCode = NtQueryInformationFile(hFile, &IoStatusBlock, &FileStandard, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
    SetLastNTError(errCode);

    return NT_ERROR(errCode) ? INVALID_FILE_SIZE : FileStandard.EndOfFile.QuadPart;
}
BOOL File_Delete(LPCWSTR path)
{
    static NTSTATUS(NTAPI* NtSetInformationFile)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
    if (!NtSetInformationFile) NtSetInformationFile = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtSetInformationFile");
    static NTSTATUS(NTAPI * NtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
    if (!NtCreateFile) NtCreateFile = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtCreateFile");
    static NTSTATUS(NTAPI * NtDeleteFile)(POBJECT_ATTRIBUTES   ObjectAttributes);
    if (!NtDeleteFile) NtDeleteFile = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtDeleteFile");
    OBJECT_ATTRIBUTES obj_file = {0};
    IO_STATUS_BLOCK io_file = {0};
    UNICODE_STRING ntPath;
    Path.RtlDosPathNameToNtPathName_U(path, &ntPath, NULL, NULL);
    InitializeObjectAttributes(&obj_file, &ntPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hFile;
    NTSTATUS ret = NtCreateFile(&hFile, DELETE, &obj_file, &io_file, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, 0, NULL, 0);

    // could not get handle, call and pray
    if(NT_ERROR(ret))
    {
        ret = NtDeleteFile(&obj_file);
        return NT_SUCCESS(ret);
    }

    BOOLEAN disp_info = TRUE;
    ret = NtSetInformationFile(hFile, &io_file, &disp_info,
        sizeof(disp_info), FileDispositionInformation);

    NtDeleteFile(&obj_file);

    File.Close(hFile);
    return NT_SUCCESS(ret);
}
BOOL File_Close(HANDLE hFile)
{
    NTSTATUS status = NtClose(hFile);
    SetLastNTError(status);
    return status == 0;
}
struct File File = {
    .Create = &File_Create,
    .Write = &File_Write,
    .Read = &File_Read,
    .Size = &File_GetSize,
    .Close = &File_Close,
    .Delete = &File_Delete
};
