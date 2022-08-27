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
#define PS_ATTRIBUTE_CLIENT_ID \
    PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE)
#define PS_ATTRIBUTE_IMAGE_NAME \
    PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_IMAGE_INFO \
    PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE)
#define PS_ATTRIBUTE_STD_HANDLE_INFO \
    PsAttributeValue(PsAttributeStdHandleInfo, FALSE, TRUE, FALSE)
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
    PS_ATTRIBUTE Attributes[4];
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

typedef struct _SECTION_IMAGE_INFORMATION
{
    PVOID TransferAddress; // Entry point
    ULONG ZeroBits;
    SIZE_T MaximumStackSize;
    SIZE_T CommittedStackSize;
    ULONG SubSystemType;
    union
    {
        struct
        {
            USHORT SubSystemMinorVersion;
            USHORT SubSystemMajorVersion;
        } s1;
        ULONG SubSystemVersion;
    } u1;
    union
    {
        struct
        {
            USHORT MajorOperatingSystemVersion;
            USHORT MinorOperatingSystemVersion;
        } s2;
        ULONG OperatingSystemVersion;
    } u2;
    USHORT ImageCharacteristics;
    USHORT DllCharacteristics;
    USHORT Machine;
    BOOLEAN ImageContainsCode;
    union
    {
        UCHAR ImageFlags;
        struct
        {
            UCHAR ComPlusNativeReady : 1;
            UCHAR ComPlusILOnly : 1;
            UCHAR ImageDynamicallyRelocated : 1;
            UCHAR ImageMappedFlat : 1;
            UCHAR BaseBelow4gb : 1;
            UCHAR ComPlusPrefer32bit : 1;
            UCHAR Reserved : 2;
        } s3;
    } u3;
    ULONG LoaderFlags;
    ULONG ImageFileSize;
    ULONG CheckSum;
} SECTION_IMAGE_INFORMATION, * PSECTION_IMAGE_INFORMATION;
typedef struct _PS_STD_HANDLE_INFO
{
    union
    {
        ULONG Flags;
        struct
        {
            ULONG StdHandleState : 2;
            ULONG PseudoHandleMask : 3;
        };
    };
    ULONG StdHandleSubsystemType;
} PS_STD_HANDLE_INFO, * PPS_STD_HANDLE_INFO;
typedef struct _RTL_USER_PROCESS_INFORMATION {
    ULONG Size;
    HANDLE Process;
    HANDLE Thread;
    CLIENT_ID ClientId;
    SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, * PRTL_USER_PROCESS_INFORMATION;
#pragma endregion
#if 1
#ifdef _WIN64
#define callc __fastcall
#else
#define callc __stdcall
#endif


PHANDLE Process_Create(const WCHAR* fileName, const WCHAR* params)
{
    static NTSTATUS(callc * NtCreateUserProcess)(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList) = NULL;
    if (!NtCreateUserProcess) NtCreateUserProcess = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtCreateUserProcess");
    static NTSTATUS(callc * RtlCreateProcessParametersEx)(PRTL_USER_PROCESS_PARAMETERS * pProcessParameters, PUNICODE_STRING ImagePathName, PUNICODE_STRING DllPath, PUNICODE_STRING CurrentDirectory, PUNICODE_STRING CommandLine, PVOID Environment, PUNICODE_STRING WindowTitle, PUNICODE_STRING DesktopInfo, PUNICODE_STRING ShellInfo, PUNICODE_STRING RuntimeData, ULONG Flags) = NULL;
    if (!RtlCreateProcessParametersEx) RtlCreateProcessParametersEx = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "RtlCreateProcessParametersEx");
    static NTSTATUS(callc * RtlDestroyProcessParameters)(PRTL_USER_PROCESS_PARAMETERS ProcessParameters);
    if (!RtlDestroyProcessParameters) RtlDestroyProcessParameters = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "RtlDestroyProcessParameters");

    UNICODE_STRING ImageName = { 0 }, CommandLine = { 0 }, ImagePath = { 0 };
    HANDLE hProcess = NULL, hThread = NULL;
    WCHAR wImagePath[MAX_PATH] = { 0 }, wParams[MAX_PATH] = { 0 };
    PRTL_USER_PROCESS_PARAMETERS processParams = NULL;
    // https://offensivedefence.co.uk/posts/ntcreateuserprocess/
    OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
    DWORD wImagePathLength =
        Path.SearchPathW(NULL, fileName, L".exe", sizeof(wImagePath) / sizeof(WCHAR),
            wImagePath, NULL);

    RtlInitUnicodeStringEx(&ImagePath, wImagePath);
    NTSTATUS status = Path.RtlDosPathNameToNtPathName_U(wImagePath, &ImageName, NULL, NULL);

    wstrcpy(wParams, L"\"");
    wstrcpy(wParams + 1, wImagePath);
    wstrcpy(wParams + 1 + wImagePathLength, L"\"");
    if (params && params[0]) {
        wParams[wImagePathLength + 2] = L' ';
        wstrcpy(wParams + 3 + wImagePathLength, params);
    }
    RtlInitUnicodeStringEx(&CommandLine, wParams);
    PUNICODE_STRING CurrentDir =
        &NtGetPeb()->ProcessParameters->CurrentDirectory.DosPath;

    status = RtlCreateProcessParametersEx(&processParams, &ImagePath, NULL, CurrentDir,
        &CommandLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);
    if(NT_ERROR(status))
    {
        SetLastNTError(status);
        return INVALID_HANDLE_VALUE;
    }
    PS_CREATE_INFO createInfo = {sizeof(createInfo) };
    createInfo.State = PsCreateInitialState;
    createInfo.InitState.InitFlags = 1;
    PPS_STD_HANDLE_INFO stdHandleInfo = NativeLib.Memory.AllocateHeap(sizeof(PS_STD_HANDLE_INFO), true);
    PCLIENT_ID clientId = NativeLib.Memory.AllocateHeap(sizeof(PS_ATTRIBUTE), true);
    PSECTION_IMAGE_INFORMATION SecImgInfo = NativeLib.Memory.AllocateHeap(sizeof(SECTION_IMAGE_INFORMATION), true);
    PPS_ATTRIBUTE_LIST attributeList = NativeLib.Memory.AllocateHeap(sizeof(PS_ATTRIBUTE_LIST), true);

    attributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);
    attributeList->Attributes[0].Attribute = PS_ATTRIBUTE_CLIENT_ID;
    attributeList->Attributes[0].Size = sizeof(CLIENT_ID);
    attributeList->Attributes[0].ValuePtr = clientId;

    attributeList->Attributes[1].Attribute = PS_ATTRIBUTE_IMAGE_INFO;
    attributeList->Attributes[1].Size = sizeof(SECTION_IMAGE_INFORMATION);
    attributeList->Attributes[1].ValuePtr = SecImgInfo;

    attributeList->Attributes[2].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    attributeList->Attributes[2].Size = ImageName.Length;
    attributeList->Attributes[2].ValuePtr = ImageName.Buffer;

    attributeList->Attributes[3].Attribute = PS_ATTRIBUTE_STD_HANDLE_INFO;
    attributeList->Attributes[3].Size = sizeof(PS_STD_HANDLE_INFO);
    attributeList->Attributes[3].ValuePtr = stdHandleInfo;

    status = NtCreateUserProcess(&hProcess, &hThread, MAXIMUM_ALLOWED, MAXIMUM_ALLOWED, &objAttr, &objAttr, 0, 0, processParams, &createInfo, attributeList);

    SetLastNTError(status);
    if (SecImgInfo) NativeLib.Memory.FreeHeap(SecImgInfo);
    if (clientId) NativeLib.Memory.FreeHeap(clientId);
    if (stdHandleInfo) NativeLib.Memory.FreeHeap(stdHandleInfo);
    if (attributeList) NativeLib.Memory.FreeHeap(attributeList);
    if (processParams) RtlDestroyProcessParameters(processParams);
    return hProcess;
}
#endif

DWORD Process_FindByName(const WCHAR* processName)
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
    for(;;)
    {
        status = NtQuerySystemInformation(SystemProcessInformation, psi, Size, &Size);
        if (NT_SUCCESS(status)) break;
        NativeLib.Memory.ReAllocHeap(buffer, Size, true);
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
#define IS_ATOM(x) (((ULONG_PTR)(x) > 0x0) && ((ULONG_PTR)(x) < 0x10000))
#define QUERY_WINDOW_UNIQUE_PROCESS_ID 0
DWORD Process_FindByWindow(LPCWSTR lpszClass, LPCWSTR lpszWindow, HWND hwndParent, HWND hwndChildAfter)
{
    // TODO: This needs to load win32u.dll
    static HWND(NTAPI* NtUserFindWindowEx)(PVOID hwndParent, PVOID hwndChild, PUNICODE_STRING ClassName, PUNICODE_STRING WindowName, ULONG Type) = NULL;
    if (NtUserFindWindowEx) NtUserFindWindowEx = NativeLib.Library.GetModuleFunction(L"win32u.dll", "NtUserFindWindowEx");
    static DWORD_PTR(NTAPI * NtUserQueryWindow)(HWND hWnd, DWORD Index);
    if (NtUserQueryWindow) NtUserQueryWindow = NativeLib.Library.GetModuleFunction(L"win32u.dll", "NtUserQueryWindow");
    UNICODE_STRING ucClassName, * pucClassName = NULL;
    UNICODE_STRING ucWindowName, * pucWindowName = NULL;

    if (IS_ATOM(lpszClass))
    {
        ucClassName.Length = 0;
        ucClassName.Buffer = lpszClass;
        pucClassName = &ucClassName;
    }
    else if (lpszClass != NULL)
    {
        RtlInitUnicodeStringEx(&ucClassName,
            lpszClass);
        pucClassName = &ucClassName;
    }

    if (lpszWindow != NULL)
    {
        RtlInitUnicodeStringEx(&ucWindowName,
            lpszWindow);
        pucWindowName = &ucWindowName;
    }

    HWND hWnd = NtUserFindWindowEx(hwndParent,
        hwndChildAfter,
        pucClassName,
        pucWindowName,
        0);
    return NtUserQueryWindow(hWnd, QUERY_WINDOW_UNIQUE_PROCESS_ID);
}

NTSTATUS Process_Terminate(HANDLE processHandle, NTSTATUS exitStatus)
{
    static NTSTATUS(NTAPI * NtTerminateProcess)(HANDLE ProcessHandle, NTSTATUS ExitStatus) = NULL;
    if (!NtTerminateProcess) NtTerminateProcess = NativeLib.Library.GetModuleFunction(L"ntdll.dll", "NtTerminateProcess");
    NTSTATUS status = NtTerminateProcess(processHandle, exitStatus);
    SetLastNTError(status);
    return status;
}

struct Process Process = {
    .Create = &Process_Create,
    .FindByName = &Process_FindByName,
    .FindByWindow = &Process_FindByWindow,
    .Terminate = &Process_Terminate
};

