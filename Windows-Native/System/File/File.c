#include "File.h"

static NTSTATUS(__stdcall* NtQueryInformationFile)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) = NULL;
PHANDLE File_Open()
{
}

PHANDLE File_Create()
{
};
INT64 File_GetSize(HANDLE hFile)
{
	if(!NtQueryInformationFile) NtQueryInformationFile = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtQueryInformationFile");
	FILE_STANDARD_INFORMATION FileStandard;
	IO_STATUS_BLOCK IoStatusBlock;

	NTSTATUS errCode = NtQueryInformationFile(hFile,
	                                          &IoStatusBlock,
	                                          &FileStandard,
	                                          sizeof(FILE_STANDARD_INFORMATION),
	                                          FileStandardInformation);
	if (NT_ERROR(errCode))
	{
		SetLastNTError(errCode);
		return -1;
	}

	return FileStandard.EndOfFile.QuadPart;
}
BOOL File_Close(HANDLE hFile)
{
	return NtClose(hFile) == 0;
}
struct File File = {
	.Open = &File_Open,
	.Create = &File_Create,
	.Size = &File_GetSize,
	.Close = &File_Close,
};
