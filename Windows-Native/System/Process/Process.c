#include <framework.h>
#include "Process.h"
#define OffsetToPtr(Snapshot, Offset)                                          \
  ((ULONG_PTR)((Snapshot) + 1) + (ULONG_PTR)(Offset))
#define ERROR_NO_MORE_FILES              18L
typedef struct tagPROCESSENTRY32W {
    DWORD     dwSize;
    DWORD     cntUsage;
    DWORD     th32ProcessID;
    ULONG_PTR th32DefaultHeapID;
    DWORD     th32ModuleID;
    DWORD     cntThreads;
    DWORD     th32ParentProcessID;
    LONG      pcPriClassBase;
    DWORD     dwFlags;
    WCHAR     szExeFile[MAX_PATH];
} PROCESSENTRY32W, * LPPROCESSENTRY32W;
typedef struct _TH32SNAPSHOT
{
    /* Heap list */
    ULONG HeapListCount;
    ULONG HeapListIndex;
    ULONG_PTR HeapListOffset;
    /* Module list */
    ULONG ModuleListCount;
    ULONG ModuleListIndex;
    ULONG_PTR ModuleListOffset;
    /* Process list */
    ULONG ProcessListCount;
    ULONG ProcessListIndex;
    ULONG_PTR ProcessListOffset;
    /* Thread list */
    ULONG ThreadListCount;
    ULONG ThreadListIndex;
    ULONG_PTR ThreadListOffset;
} TH32SNAPSHOT, * PTH32SNAPSHOT;
typedef struct _PS_CREATE_INFO PS_CREATE_INFO, *PPS_CREATE_INFO;
typedef struct _PS_ATTRIBUTE_LIST PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;



PHANDLE Process_Create(const WCHAR* fileName, const WCHAR* params)
{
    static NTSTATUS(__stdcall * NtCreateUserProcess)(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessAccess, ACCESS_MASK ThreadAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList);
    PHANDLE hProcess = NULL;
    PHANDLE hThread = NULL;
    //NtCreateUserProcess(hProcess, hThread,  )
	return false;
}

DWORD Process_Exists(const WCHAR* processName)
{
    __debugbreak();
    static NTSTATUS(__stdcall* NtMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID * BaseAddress, ULONG ZeroBits, ULONG CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect);
    if (!NtMapViewOfSection) NtMapViewOfSection = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtMapViewOfSection");
    static NTSTATUS(__stdcall * NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
    if(!NtUnmapViewOfSection) NtUnmapViewOfSection = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtUnmapViewOfSection");
	static HANDLE(__stdcall * CreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);
    if (!CreateToolhelp32Snapshot) CreateToolhelp32Snapshot = NativeLib.Library.GetModuleFunction(L"Kernel32.dll", "CreateToolhelp32Snapshot");

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);

    PTH32SNAPSHOT Snapshot = NULL;
    LARGE_INTEGER SOffset = {0,0};
    SIZE_T ViewSize = 0;

    NTSTATUS status = NtMapViewOfSection(hSnapshot,
                                         NtCurrentProcess(),
                                         &Snapshot,
                                         0,
                                         0,
										 &SOffset,
                                         &ViewSize,
                                         ViewShare,
                                         0,
										 PAGE_READWRITE);
    DWORD pId = -1;
    if (!NT_ERROR(status))
    {
    	LPPROCESSENTRY32W entries = (LPPROCESSENTRY32W)OffsetToPtr(Snapshot, Snapshot->ProcessListOffset);

        for (int i = 0; i < Snapshot->ProcessListCount; ++i)
        {
            if(strcmpW(processName, entries[i].szExeFile))
	            continue;
            pId = entries[i].th32ProcessID;
        	break;
        }
    } else  {
        SetLastNTError(status);
    }
    NtUnmapViewOfSection(NtCurrentProcess(), (PVOID)Snapshot);
    NtClose(hSnapshot);
    return pId;
#if 0
	static BOOL(__stdcall * Process32FirstW)(HANDLE, LPPROCESSENTRY32W);

	if (!Process32FirstW) Process32FirstW = NativeLib.Library.GetModuleFunction(L"Kernel32.dll", "Process32FirstW");
	static BOOL(__stdcall * Process32NextW)(HANDLE, LPPROCESSENTRY32W);
	if (!Process32NextW) Process32NextW = NativeLib.Library.GetModuleFunction(L"Kernel32.dll", "Process32NextW");
	static HANDLE(__stdcall * CreateToolhelp32Snapshot)(DWORD, DWORD);
	if(!CreateToolhelp32Snapshot) CreateToolhelp32Snapshot = NativeLib.Library.GetModuleFunction(L"Kernel32.dll", "CreateToolhelp32Snapshot");

	HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry;
	entry.dwSize = sizeof(PROCESSENTRY32W);
	Process32FirstW(handle, &entry);
	do
	{
		if (!strcmpW(processName, entry.szExeFile))
			return entry.th32ProcessID;
	} while (Process32NextW(handle, &entry));
#endif

    return 0;
}

NTSTATUS Process_Terminate(HANDLE processHandle, NTSTATUS exitStatus)
{
	static NTSTATUS(NTAPI * NtTerminateProcess)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
	if(!NtTerminateProcess) NtTerminateProcess = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtTerminateProcess");
	return NtTerminateProcess(processHandle, exitStatus);
}
struct Process Process = {
	.Create = &Process_Create,
	.Exists = &Process_Exists,
	.Terminate = &Process_Terminate
};

#pragma region Structs
typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;
typedef enum _PS_CREATE_STATE
{
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName, // Debugger specified
    PsCreateSuccess,
    PsCreateMaximumStates
} PS_CREATE_STATE;
typedef struct _PS_CREATE_INFO
{
    SIZE_T Size;
    PS_CREATE_STATE State;
    union
    {
        // PsCreateInitialState
        struct
        {
            union
            {
                ULONG InitFlags;
                struct
                {
                    UCHAR WriteOutputOnExit : 1;
                    UCHAR DetectManifest : 1;
                    UCHAR IFEOSkipDebugger : 1;
                    UCHAR IFEODoNotPropagateKeyState : 1;
                    UCHAR SpareBits1 : 4;
                    UCHAR SpareBits2 : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                };
            };
            ACCESS_MASK AdditionalFileAccess;
        } InitState;

        // PsCreateFailOnSectionCreate
        struct
        {
            HANDLE FileHandle;
        } FailSection;

        // PsCreateFailExeFormat
        struct
        {
            USHORT DllCharacteristics;
        } ExeFormat;

        // PsCreateFailExeName
        struct
        {
            HANDLE IFEOKey;
        } ExeName;

        // PsCreateSuccess
        struct
        {
            union
            {
                ULONG OutputFlags;
                struct
                {
                    UCHAR ProtectedProcess : 1;
                    UCHAR AddressSpaceOverride : 1;
                    UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
                    UCHAR ManifestDetected : 1;
                    UCHAR ProtectedProcessLight : 1;
                    UCHAR SpareBits1 : 3;
                    UCHAR SpareBits2 : 8;
                    USHORT SpareBits3 : 16;
                };
            };
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, * PPS_CREATE_INFO;
#pragma endregion