#include "File.h"
#define INVALID_FILE_SIZE                0xFFFFFFFF
#define ERROR_FILE_NOT_FOUND             2L
#define ERROR_FILE_EXISTS                80L
#define ERROR_ALREADY_EXISTS             183L

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
#define ERROR_PATH_NOT_FOUND             3
#define CREATE_NEW                         1
#define CREATE_ALWAYS                     2
#define OPEN_EXISTING                     3
#define OPEN_ALWAYS                         4
#define TRUNCATE_EXISTING                 5

#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008
#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080
#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_OPEN_REMOTE_INSTANCE               0x00000400
#define FILE_RANDOM_ACCESS                      0x00000800
#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000
#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_OPEN_REPARSE_POINT                 0x00200000
#define FILE_OPEN_NO_RECALL                     0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x00800000
#define FILE_COPY_STRUCTURED_STORAGE            0x00000041
#define FILE_STRUCTURED_STORAGE                 0x00000441

#define FILE_SUPERSEDE                            0x00000000
#define FILE_OPEN                                0x00000001
#define FILE_CREATE                                0x00000002
#define FILE_OPEN_IF                            0x00000003
#define FILE_OVERWRITE                            0x00000004
#define FILE_OVERWRITE_IF                        0x00000005
#define FILE_MAXIMUM_DISPOSITION                0x00000005

#define FILE_SUPERSEDED                         0x00000000
#define FILE_OPENED                             0x00000001
#define FILE_CREATED                            0x00000002
#define FILE_OVERWRITTEN                        0x00000003
#define FILE_EXISTS                             0x00000004
#define FILE_DOES_NOT_EXIST                     0x00000005

#define FILE_FLAG_WRITE_THROUGH                    0x80000000
#define FILE_FLAG_OVERLAPPED                    0x40000000
#define FILE_FLAG_NO_BUFFERING                    0x20000000
#define FILE_FLAG_RANDOM_ACCESS                    0x10000000
#define FILE_FLAG_SEQUENTIAL_SCAN                0x08000000
#define FILE_FLAG_DELETE_ON_CLOSE                0x04000000
#define FILE_FLAG_BACKUP_SEMANTICS                0x02000000
#define FILE_FLAG_POSIX_SEMANTICS                0x01000000
#define FILE_FLAG_SESSION_AWARE                    0x00800000
#define FILE_FLAG_OPEN_REPARSE_POINT            0x00200000
#define FILE_FLAG_OPEN_NO_RECALL                0x00100000
#define FILE_FLAG_FIRST_PIPE_INSTANCE            0x00080000
#define FILE_ATTRIBUTE_VALID_FLAGS              0x00007fb7
#define FILE_ATTRIBUTE_VALID_SET_FLAGS          0x000031a7
#define FILE_ATTRIBUTE_DIRECTORY                0x00000010
#define FILE_READ_ATTRIBUTES                      0x0080

#define OBJ_CASE_INSENSITIVE   0x00000040L


static NTSTATUS(__stdcall* NtQueryInformationFile)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) = NULL;

NTSTATUS RtlDosPathNameToNtPathName_U(PCWSTR DosName, PUNICODE_STRING NtName, PWSTR* PartName, PRTL_RELATIVE_NAME_U RelativeName)
{
    static NTSTATUS(__stdcall * RtlpDosPathNameToRelativeNtPathName_Ustr)(PCWSTR DosFileName, PUNICODE_STRING NtFileName, PWSTR * FilePart, PRTL_RELATIVE_NAME_U RelativeName);
    if (!RtlpDosPathNameToRelativeNtPathName_Ustr) RtlpDosPathNameToRelativeNtPathName_Ustr = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "RtlDosLongPathNameToNtPathName_U_WithStatus");
    return RtlpDosPathNameToRelativeNtPathName_Ustr(DosName, NtName, PartName, RelativeName);
}
PHANDLE File_Create(PWCHAR fileName, DWORD Access, DWORD ShareMode, DWORD CreationDisposition, DWORD FlagsAndAttributes)
{
    static NTSTATUS(__stdcall * NtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
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
    RTL_RELATIVE_NAME_U relName;
    if (NT_ERROR(RtlDosPathNameToNtPathName_U(fileName, &NtPathU, NULL, &relName)))
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
UINT64 File_GetSize(HANDLE hFile)
{
    if (!NtQueryInformationFile) NtQueryInformationFile = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtQueryInformationFile");
    FILE_STANDARD_INFORMATION FileStandard = { 0 };
    IO_STATUS_BLOCK IoStatusBlock = { 0 };

    NTSTATUS errCode = NtQueryInformationFile(hFile, &IoStatusBlock, &FileStandard, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
    SetLastNTError(errCode);
    if (NT_ERROR(errCode))
    {
        return INVALID_FILE_SIZE;
    }

    return FileStandard.EndOfFile.QuadPart;
}
BOOL File_Close(HANDLE hFile)
{
    NTSTATUS status = NtClose(hFile);
    SetLastNTError(status);
    return status == 0;
}
struct File File = {
    .Create = &File_Create,
    .Size = &File_GetSize,
    .Close = &File_Close,
};
