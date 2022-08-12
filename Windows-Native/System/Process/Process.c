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
typedef struct _PS_CREATE_INFO PS_CREATE_INFO, * PPS_CREATE_INFO;
typedef struct _PS_ATTRIBUTE_LIST PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;



PHANDLE Process_Create(const WCHAR* fileName, const WCHAR* params)
{
    static NTSTATUS(__stdcall * NtCreateUserProcess)(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessAccess, ACCESS_MASK ThreadAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList) = NULL;
    PHANDLE hProcess = NULL;
    PHANDLE hThread = NULL;
    //NtCreateUserProcess(hProcess, hThread,  )
    return false;
}

DWORD Process_Exists(const WCHAR* processName)
{
    static NTSTATUS(__stdcall * NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) = NULL;
    if (!NtQuerySystemInformation) NtQuerySystemInformation = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtQuerySystemInformation");
    NTSTATUS status;
    ULONG Size = 0;
    DWORD pId = -1;
    if (NT_SUCCESS(status = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &Size)))
    {
        SetLastNTError(status);
        return -1;
    }
    PVOID buffer = NativeLib.Memory.AllocateVirtual(Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer)
    {
        __debugbreak();
        return -1;
    }
    PSYSTEM_PROCESS_INFORMATION psi = buffer;
    if (!NT_SUCCESS(status = NtQuerySystemInformation(SystemProcessInformation, psi, Size, NULL)))
    {
        SetLastNTError(status);
        NativeLib.Memory.FreeVirtual(buffer, Size, MEM_RELEASE);
        return -1;
    }
    while (psi->NextEntryOffset)
    {
        psi = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)psi + psi->NextEntryOffset);
        if (strcmpW(psi->ImageName.Buffer, processName)) continue;
        pId = (DWORD)psi->UniqueProcessId;
        break;
    }

    NativeLib.Memory.FreeVirtual(buffer, Size, MEM_RELEASE);
    return pId;
}

NTSTATUS Process_Terminate(HANDLE processHandle, NTSTATUS exitStatus)
{
    static NTSTATUS(NTAPI * NtTerminateProcess)(HANDLE ProcessHandle, NTSTATUS ExitStatus) = NULL;
    if (!NtTerminateProcess) NtTerminateProcess = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtTerminateProcess");
    return NtTerminateProcess(processHandle, exitStatus);
}
struct Process Process = {
    //.Create = &Process_Create,
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