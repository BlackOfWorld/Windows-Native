#include <framework.h>
#include "Process.h"

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
typedef struct _PS_CREATE_INFO PS_CREATE_INFO, *PPS_CREATE_INFO;
typedef struct _PS_ATTRIBUTE_LIST PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;



PHANDLE Process_Create(const WCHAR* fileName, const WCHAR* params)
{
    static NTSTATUS(__stdcall * NtCreateUserProcess)(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessAccess, ACCESS_MASK ThreadAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList);
    //NtCreateUserProcess()
	return false;
}

DWORD Process_Exists(const WCHAR* processName)
{
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
	return 0;
}

NTSTATUS Process_Terminate(HANDLE handle, NTSTATUS exitStatus)
{
	static NTSTATUS(NTAPI * NtTerminateProcess)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
	if(!NtTerminateProcess) NtTerminateProcess = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtTerminateProcess");
	return NtTerminateProcess(handle, exitStatus);
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