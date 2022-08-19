#include <framework.h>
#include "Process.h"
#include "System/Filesystem/File.h"
#include "System/Filesystem/Path.h"

#pragma region Defines

#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED              0x01

#define PS_ATTRIBUTE_NUMBER_MASK 0x0000ffff
#define PS_ATTRIBUTE_THREAD 0x00010000 // may be used with thread creation
#define PS_ATTRIBUTE_INPUT 0x00020000 // input only
#define PS_ATTRIBUTE_ADDITIVE 0x00040000 // "accumulated" e.g. bitmasks, counters, etc.
#define PsAttributeValue(Number, Thread, Input, Additive) \
    (((Number) & PS_ATTRIBUTE_NUMBER_MASK) | \
    ((Thread) ? PS_ATTRIBUTE_THREAD : 0) | \
    ((Input) ? PS_ATTRIBUTE_INPUT : 0) | \
    ((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))
#define PS_ATTRIBUTE_IMAGE_NAME \
    PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE)
#define PROCESS_TERMINATE                  (0x0001)
#define PROCESS_CREATE_THREAD              (0x0002)
#define PROCESS_SET_SESSIONID              (0x0004)
#define PROCESS_VM_OPERATION               (0x0008)
#define PROCESS_VM_READ                    (0x0010)
#define PROCESS_VM_WRITE                   (0x0020)
#define PROCESS_DUP_HANDLE                 (0x0040)
#define PROCESS_CREATE_PROCESS             (0x0080)
#define PROCESS_SET_QUOTA                  (0x0100)
#define PROCESS_SET_INFORMATION            (0x0200)
#define PROCESS_QUERY_INFORMATION          (0x0400)
#define PROCESS_SUSPEND_RESUME             (0x0800)
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)
#define PROCESS_SET_LIMITED_INFORMATION    (0x2000)
//

#if (NTDDI_VERSION >= NTDDI_VISTA)
#define PROCESS_ALL_ACCESS        (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
                                   0xFFFF)
#else
#define PROCESS_ALL_ACCESS        (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
                                   0xFFF)
#endif

//
#define THREAD_TERMINATE                 (0x0001)
#define THREAD_SUSPEND_RESUME            (0x0002)
#define THREAD_GET_CONTEXT               (0x0008)
#define THREAD_SET_CONTEXT               (0x0010)
#define THREAD_QUERY_INFORMATION         (0x0040)
#define THREAD_SET_INFORMATION           (0x0020)
#define THREAD_SET_THREAD_TOKEN          (0x0080)
#define THREAD_IMPERSONATE               (0x0100)
#define THREAD_DIRECT_IMPERSONATION      (0x0200)
#define THREAD_SET_LIMITED_INFORMATION   (0x0400)  // winnt
#define THREAD_QUERY_LIMITED_INFORMATION (0x0800)  // winnt
#define THREAD_RESUME                    (0x1000)  // winnt

#if (NTDDI_VERSION >= NTDDI_VISTA)
#define THREAD_ALL_ACCESS         (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
                                   0xFFFF)
#else
#define THREAD_ALL_ACCESS         (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
                                   0x3FF)
#endif
#pragma endregion
#pragma region Structs
typedef enum _PS_ATTRIBUTE_NUM
{
    PsAttributeParentProcess, // in HANDLE
    PsAttributeDebugObject, // in HANDLE
    PsAttributeToken, // in HANDLE
    PsAttributeClientId, // out PCLIENT_ID
    PsAttributeTebAddress, // out PTEB *
    PsAttributeImageName, // in PWSTR
    PsAttributeImageInfo, // out PSECTION_IMAGE_INFORMATION
    PsAttributeMemoryReserve, // in PPS_MEMORY_RESERVE
    PsAttributePriorityClass, // in UCHAR
    PsAttributeErrorMode, // in ULONG
    PsAttributeStdHandleInfo, // 10, in PPS_STD_HANDLE_INFO
    PsAttributeHandleList, // in HANDLE[]
    PsAttributeGroupAffinity, // in PGROUP_AFFINITY
    PsAttributePreferredNode, // in PUSHORT
    PsAttributeIdealProcessor, // in PPROCESSOR_NUMBER
    PsAttributeUmsThread, // ? in PUMS_CREATE_THREAD_ATTRIBUTES
    PsAttributeMitigationOptions, // in PPS_MITIGATION_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_POLICY_*) // since WIN8
    PsAttributeProtectionLevel, // in PS_PROTECTION // since WINBLUE
    PsAttributeSecureProcess, // in PPS_TRUSTLET_CREATE_ATTRIBUTES, since THRESHOLD
    PsAttributeJobList, // in HANDLE[]
    PsAttributeChildProcessPolicy, // 20, in PULONG (PROCESS_CREATION_CHILD_PROCESS_*) // since THRESHOLD2
    PsAttributeAllApplicationPackagesPolicy, // in PULONG (PROCESS_CREATION_ALL_APPLICATION_PACKAGES_*) // since REDSTONE
    PsAttributeWin32kFilter, // in PWIN32K_SYSCALL_FILTER
    PsAttributeSafeOpenPromptOriginClaim, // in
    PsAttributeBnoIsolation, // in PPS_BNO_ISOLATION_PARAMETERS // since REDSTONE2
    PsAttributeDesktopAppPolicy, // in PULONG (PROCESS_CREATION_DESKTOP_APP_*)
    PsAttributeChpe, // in BOOLEAN // since REDSTONE3
    PsAttributeMitigationAuditOptions, // in PPS_MITIGATION_AUDIT_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_AUDIT_POLICY_*) // since 21H1
    PsAttributeMachineType, // in WORD // since 21H2
    PsAttributeComponentFilter,
    PsAttributeEnableOptionalXStateFeatures, // since WIN11
    PsAttributeMax
} PS_ATTRIBUTE_NUM;
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

typedef struct _SECTION_IMAGE_INFORMATION {
    PVOID EntryPoint;
    ULONG StackZeroBits;
    ULONG StackReserved;
    ULONG StackCommit;
    ULONG ImageSubsystem;
    WORD SubSystemVersionLow;
    WORD SubSystemVersionHigh;
    ULONG Unknown1;
    ULONG ImageCharacteristics;
    ULONG ImageMachineType;
    ULONG Unknown2[3];
} SECTION_IMAGE_INFORMATION, * PSECTION_IMAGE_INFORMATION;

typedef struct _RTL_USER_PROCESS_INFORMATION {
    ULONG Size;
    HANDLE Process;
    HANDLE Thread;
    CLIENT_ID ClientId;
    SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, * PRTL_USER_PROCESS_INFORMATION;
#pragma endregion
#if 1

extern VOID NTAPI RtlCopyUnicodeString(PUNICODE_STRING DestinationString,
                                       const PUNICODE_STRING SourceString);

PHANDLE Process_Create(const WCHAR* fileName, const WCHAR* params)
{
    static NTSTATUS(__stdcall * NtCreateUserProcess)(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessAccess, ACCESS_MASK ThreadAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList) = NULL;
    if (!NtCreateUserProcess) NtCreateUserProcess = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtCreateUserProcess");
    static NTSTATUS(__stdcall * RtlCreateProcessParametersEx)(PRTL_USER_PROCESS_PARAMETERS* pProcessParameters, PUNICODE_STRING ImagePathName, PUNICODE_STRING DllPath, PUNICODE_STRING CurrentDirectory, PUNICODE_STRING CommandLine, PVOID Environment, PUNICODE_STRING WindowTitle, PUNICODE_STRING DesktopInfo, PUNICODE_STRING ShellInfo, PUNICODE_STRING RuntimeData, DWORD Flags) = NULL;
    if(!RtlCreateProcessParametersEx) RtlCreateProcessParametersEx = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "RtlCreateProcessParameters");
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    
    WCHAR wImagePath[MAX_PATH] = {0};
    // https://offensivedefence.co.uk/posts/ntcreateuserprocess/

    NTSTATUS status =
        Path.SearchPathW(NULL, fileName, L".exe", sizeof(wImagePath) / sizeof(WCHAR),
                         wImagePath, NULL);

    UNICODE_STRING ImagePath = {0}, CommandLine = {0};
    status = Path.RtlDosPathNameToNtPathName_U(wImagePath, &ImagePath, NULL, NULL);

    RtlInitUnicodeStringEx(&CommandLine, params);
    PRTL_USER_PROCESS_PARAMETERS processParams = NULL;

    UNICODE_STRING path =
        NtGetPeb()->ProcessParameters->CurrentDirectory.DosPath;

    /*
    wchar_t wCurrentDir[MAX_PATH]= {0};
    UNICODE_STRING CurrentDir = {.Buffer = &wCurrentDir, .Length = 0, .MaximumLength = 0};
    RtlCopyUnicodeString(&CurrentDir, &NtGetPeb()->ProcessParameters->CurrentDirectory.DosPath);*/

    PUNICODE_STRING CurrentDir =
        &NtGetPeb()->ProcessParameters->CurrentDirectory.DosPath;
        
    status = Path.RtlDosPathNameToNtPathName_U(CurrentDir->Buffer, CurrentDir, NULL, NULL);
    status = RtlCreateProcessParametersEx(&processParams, &ImagePath, NULL, CurrentDir, 
        NULL, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);

    if (status)
        __debugbreak();
    PS_CREATE_INFO createInfo;
    createInfo.Size = sizeof(createInfo);
    createInfo.State = PsCreateInitialState;

    PPS_ATTRIBUTE_LIST attributeList = NativeLib.Memory.AllocateHeap(sizeof(PS_ATTRIBUTE), true);
    attributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);
    attributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    attributeList->Attributes[0].Size = ImagePath.Length;
    attributeList->Attributes[0].Value = (ULONG_PTR)ImagePath.Buffer;

    status = NtCreateUserProcess(&hProcess, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0, 0, processParams, &createInfo, attributeList);
    if (status)
        __debugbreak();
    SetLastNTError(status);
    return false;
}
#endif

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
    PVOID buffer = NativeLib.Memory.AllocateHeap(Size, true);
    if (!buffer)
    {
        __debugbreak();
        return -1;
    }
    PSYSTEM_PROCESS_INFORMATION psi = buffer;
    if (!NT_SUCCESS(status = NtQuerySystemInformation(SystemProcessInformation, psi, Size, NULL)))
    {
        SetLastNTError(status);
        NativeLib.Memory.FreeHeap(buffer);
        return -1;
    }
    while (psi->NextEntryOffset)
    {
        psi = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)psi + psi->NextEntryOffset);
        if (strcmpW(psi->ImageName.Buffer, processName)) continue;
        pId = (DWORD)psi->UniqueProcessId;
        break;
    }

    NativeLib.Memory.FreeHeap(buffer);
    return pId;
}

NTSTATUS Process_Terminate(HANDLE processHandle, NTSTATUS exitStatus)
{
    static NTSTATUS(NTAPI * NtTerminateProcess)(HANDLE ProcessHandle, NTSTATUS ExitStatus) = NULL;
    if (!NtTerminateProcess) NtTerminateProcess = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtTerminateProcess");
    return NtTerminateProcess(processHandle, exitStatus);
}

struct Process Process = {
    .Create = &Process_Create,
    .Exists = &Process_Exists,
    .Terminate = &Process_Terminate
};

