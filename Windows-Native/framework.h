#pragma once
#include <intrin.h>
#include <immintrin.h>
#define MAXIMUM_SUPPORTED_EXTENSION     512
#define SIZE_OF_80387_REGISTERS      80
struct
{
    char cpu_FSRM;       //Fast Short REP MOV https://www-ssl.intel.com/content/www/us/en/architecture-and-technology/64-ia-32-architectures-optimization-manual.html
    char cpu_SGX;        //Software Guard Extensions
    char cpu_AVX;        //Advanced Vector Extensions
    char cpu_AVX2;       //Advanced Vector Extensions 2
    char cpu_RDRAND;     //RDRAND (on-chip random number generator) feature
    char cpu_Hypervisor; //Virtualization capability
    char cpu_AES;        //AES instructions
    char cpu_SSE;        //SSE instructions
    char cpu_SSE2;       //SSE2 instructions
    char cpu_SHA;        //SHA instructions
    char cpu_FZRM;       //Fast Zero Length REP MOVSB
    char cpu_FSRS;       //Fast Short REP STOSB
    char cpu_FSRC;       //Fast Short REP CMPSB and SCASB
} CPUFeatures;

#if !(defined(_M_X64) || defined(_M_IX86) || defined(_M_ARM) || defined(_M_ARM64) || defined(_M_IA64) || defined(_M_ALPHA) || defined(_M_MIPS))
#error "This architecture is currently unsupported"
#endif

#ifdef __cplusplus
#   define EXTERNC extern "C"
#else
#   define EXTERNC
#endif

#if defined(_M_MRX000) || defined(_M_ALPHA) || defined(_M_PPC) || defined(_M_IA64) || defined(_M_AMD64) || defined(_M_ARM) || defined(_M_ARM64)
#define ALIGNMENT_MACHINE
#define UNALIGNED __unaligned
#if defined(_WIN64)
#define UNALIGNED64 __unaligned
#else
#define UNALIGNED64
#endif
#else
#undef ALIGNMENT_MACHINE
#define UNALIGNED
#define UNALIGNED64
#endif

#if defined(_WIN64)
#define MAXIMUM_PROC_PER_GROUP 64
#else
#define MAXIMUM_PROC_PER_GROUP 32
#endif

#ifdef __has_builtin
#if __has_builtin(__builtin_offsetof)
#define FIELD_OFFSET(type, field)    ((LONG)__builtin_offsetof(type, field))
#define UFIELD_OFFSET(type, field)    ((DWORD)__builtin_offsetof(type, field))
#endif
#endif

#ifndef FIELD_OFFSET
#define FIELD_OFFSET(type, field)    ((LONG)(LONG_PTR)&(((type *)0)->field))
#define UFIELD_OFFSET(type, field)    ((DWORD)(LONG_PTR)&(((type *)0)->field))
#endif

#define _ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))

#define MAXIMUM_PROCESSORS          MAXIMUM_PROC_PER_GROUP
#define MINCHAR     0x80
#define MAXCHAR     0x7f
#define MINSHORT    0x8000
#define MAXSHORT    0x7fff
#define MINLONG     0x80000000
#define MAXLONG     0x7fffffff
#define MAXBYTE     0xff
#define MAXWORD     0xffff
#define MAXDWORD    0xffffffff

//calling conventions
#define NTAPI __stdcall


// types
#if defined(_WIN64)
typedef __int64 LONGLONG;
typedef unsigned __int64 ULONGLONG;
typedef unsigned __int64 size_t;
typedef __int64          ptrdiff_t;
typedef __int64          intptr_t;

#define MAXLONGLONG                         (0x7fffffffffffffff)

typedef unsigned __int64 POINTER_64_INT;
typedef __int64 INT_PTR, * PINT_PTR;
typedef unsigned __int64 UINT_PTR, * PUINT_PTR;

typedef __int64 LONG_PTR, * PLONG_PTR;
typedef unsigned __int64 ULONG_PTR, * PULONG_PTR;

#define __int3264   __int64

#else
struct PRTL_CRITICAL_SECTION;
typedef _W64 int INT_PTR, * PINT_PTR;
typedef _W64 unsigned int UINT_PTR, * PUINT_PTR;

typedef _W64 long LONG_PTR, * PLONG_PTR;
typedef _W64 unsigned long ULONG_PTR, * PULONG_PTR;

#define __int3264   __int32

typedef unsigned int     size_t;
typedef int              ptrdiff_t;
typedef int              intptr_t;
#endif
#if defined(_WIN64)
#define POINTER_64 __ptr64
#define POINTER_32 __ptr32
#else
#define POINTER_64
#define POINTER_32
#endif


#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (PCHAR)(address) - \
                                                  (ULONG_PTR)(&((type *)0)->field)))


typedef unsigned short wchar_t;
typedef char CHAR, * PCHAR;
typedef ULONG_PTR SIZE_T, * PSIZE_T;
typedef LONG_PTR SSIZE_T, * PSSIZE_T;
#define MAX_PATH          260

#define MAKEWORD(a, b)      ((WORD)(((BYTE)(((DWORD_PTR)(a)) & 0xff)) | ((WORD)((BYTE)(((DWORD_PTR)(b)) & 0xff))) << 8))
#define MAKELONG(a, b)      ((LONG)(((WORD)(((DWORD_PTR)(a)) & 0xffff)) | ((DWORD)((WORD)(((DWORD_PTR)(b)) & 0xffff))) << 16))
#define LOWORD(l)           ((WORD)(((DWORD_PTR)(l)) & 0xffff))
#define HIWORD(l)           ((WORD)((((DWORD_PTR)(l)) >> 16) & 0xffff))
#define LOBYTE(w)           ((BYTE)(((DWORD_PTR)(w)) & 0xff))
#define HIBYTE(w)           ((BYTE)((((DWORD_PTR)(w)) >> 8) & 0xff))
#define SHRT_MIN (-32768)
#define SHRT_MAX 32767
#define USHRT_MAX 0xffff
#define INT_MIN (-2147483647 - 1)
#define INT_MAX 2147483647
#define UINT_MAX 0xffffffff
#define LONG_MIN (-2147483647L - 1)
#define LONG_MAX 2147483647L
#define ULONG_MAX 0xffffffffUL
#define LLONG_MAX 9223372036854775807LL
#define LLONG_MIN (-9223372036854775807LL - 1)
#define ULLONG_MAX 0xffffffffffffffffULL
typedef double DOUBLE;
typedef unsigned char BYTE, * PBYTE, * LPBYTE;
typedef unsigned char UCHAR, * PUCHAR;
typedef unsigned long DWORD, * PDWORD, * LPDWORD;
typedef unsigned int DWORD32;
typedef unsigned __int64 DWORD64, * PDWORD64;
typedef long LONG, * PLONG, * LPLONG;
typedef signed __int64 LONGLONG;
typedef signed int LONG32;
typedef signed __int64 LONG64, * PLONG64;
typedef const char* LPCSTR;
typedef const void* LPCVOID;
typedef const wchar_t* LPCWSTR;
typedef char* PSTR, * LPSTR;
typedef wchar_t* LPWSTR, * PWSTR;
typedef wchar_t WCHAR, * PWCHAR;
typedef unsigned __int64 QWORD;
typedef unsigned short USHORT;
typedef unsigned int UINT;
typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef unsigned int UINT32;
typedef unsigned __int64 UINT64;
typedef unsigned long ULONG, * PULONG;
typedef unsigned int ULONG32;
typedef unsigned __int64 ULONG64;
typedef unsigned __int64 ULONGLONG;
typedef short SHORT;
typedef ULONG_PTR SIZE_T;
typedef UCHAR* STRING;
typedef ULONGLONG DWORDLONG, * PDWORDLONG;
typedef float FLOAT;
typedef ULONG_PTR DWORD_PTR;
typedef int BOOL, *PBOOL, *LPBOOL;
typedef BYTE BOOLEAN, * PBOOLEAN;
typedef WCHAR* BSTR;
typedef int INT, * LPINT;
typedef signed char INT8;
typedef signed short INT16;
typedef signed int INT32;
typedef signed __int64 INT64;
typedef const wchar_t* LMCSTR;
typedef WCHAR* LMSTR;
typedef unsigned short WORD, * PWORD, * LPWORD;

typedef void VOID, * PVOID, * LPVOID;
typedef void* POINTER_32 PVOID32;
typedef void* POINTER_64 PVOID64;
typedef void* LPVOID;
typedef void* HANDLE;
typedef HANDLE* PHANDLE;
typedef HANDLE HINSTANCE;
typedef HINSTANCE HMODULE;


typedef wchar_t WCHAR;
typedef const WCHAR* LPCWCH, * PCWCH;
typedef WCHAR* NWPSTR, * LPWSTR, * PWSTR;
typedef PWSTR* PZPWSTR;
typedef const PWSTR* PCZPWSTR;
typedef WCHAR UNALIGNED* LPUWSTR, * PUWSTR;
typedef const WCHAR* LPCWSTR, * PCWSTR;
typedef PCWSTR* PZPCWSTR;
typedef const PCWSTR* PCZPCWSTR;
typedef const WCHAR UNALIGNED* LPCUWSTR, * PCUWSTR;

typedef WCHAR* PZZWSTR;
typedef const WCHAR* PCZZWSTR;
typedef WCHAR UNALIGNED* PUZZWSTR;
typedef const WCHAR UNALIGNED* PCUZZWSTR;

typedef WCHAR* PNZWCH;
typedef const WCHAR* PCNZWCH;
typedef WCHAR UNALIGNED* PUNZWCH;
typedef const WCHAR UNALIGNED* PCUNZWCH;

typedef CHAR* PCHAR, * LPCH, * PCH;
typedef const CHAR* LPCCH, * PCCH;
typedef CHAR* NPSTR, * LPSTR, * PSTR;
typedef PSTR* PZPSTR;
typedef const PSTR* PCZPSTR;
typedef const CHAR* LPCSTR, * PCSTR;
typedef PCSTR* PZPCSTR;
typedef const PCSTR* PCZPCSTR;
typedef CHAR* PZZSTR;
typedef const CHAR* PCZZSTR;
typedef CHAR* PNZCH;
typedef const CHAR* PCNZCH;

typedef short* PSHORT;
typedef long* PLONG;

typedef ULONGLONG  DWORDLONG;
typedef DWORDLONG* PDWORDLONG;


typedef ULONG_PTR KSPIN_LOCK;
typedef KSPIN_LOCK* PKSPIN_LOCK;

typedef DWORD NTSTATUS;

//error codes
#define ERROR_SUCCESS                     0L

#define STATUS_SUCCESS                    ((DWORD)0x00000000L)
#define STATUS_WAIT_0                     ((DWORD)0x00000000L)
#define STATUS_ABANDONED_WAIT_0           ((DWORD)0x00000080L)
#define STATUS_USER_APC                   ((DWORD)0x000000C0L)
#define STATUS_TIMEOUT                    ((DWORD)0x00000102L)
#define STATUS_PENDING                    ((DWORD)0x00000103L)
#define DBG_EXCEPTION_HANDLED             ((DWORD)0x00010001L)
#define DBG_CONTINUE                      ((DWORD)0x00010002L)
#define ERROR_MR_MID_NOT_FOUND            ((DWORD)0x0000013DL)
#define STATUS_SEGMENT_NOTIFICATION       ((DWORD)0x40000005L)
#define STATUS_FATAL_APP_EXIT             ((DWORD)0x40000015L)
#define DBG_REPLY_LATER                   ((DWORD)0x40010001L)
#define DBG_TERMINATE_THREAD              ((DWORD)0x40010003L)
#define DBG_TERMINATE_PROCESS             ((DWORD)0x40010004L)
#define DBG_CONTROL_C                     ((DWORD)0x40010005L)
#define DBG_PRINTEXCEPTION_C              ((DWORD)0x40010006L)
#define DBG_RIPEXCEPTION                  ((DWORD)0x40010007L)
#define DBG_CONTROL_BREAK                 ((DWORD)0x40010008L)
#define DBG_COMMAND_EXCEPTION             ((DWORD)0x40010009L)
#define DBG_PRINTEXCEPTION_WIDE_C         ((DWORD)0x4001000AL)
#define STATUS_GUARD_PAGE_VIOLATION       ((DWORD)0x80000001L)
#define STATUS_DATATYPE_MISALIGNMENT      ((DWORD)0x80000002L)
#define STATUS_BREAKPOINT                 ((DWORD)0x80000003L)
#define STATUS_SINGLE_STEP                ((DWORD)0x80000004L)
#define STATUS_LONGJUMP                   ((DWORD)0x80000026L)
#define STATUS_UNWIND_CONSOLIDATE         ((DWORD)0x80000029L)
#define DBG_EXCEPTION_NOT_HANDLED         ((DWORD)0x80010001L)
#define STATUS_ACCESS_VIOLATION           ((DWORD)0xC0000005L)
#define STATUS_IN_PAGE_ERROR              ((DWORD)0xC0000006L)
#define STATUS_INVALID_HANDLE             ((DWORD)0xC0000008L)
#define STATUS_INVALID_PARAMETER          ((DWORD)0xC000000DL)
#define STATUS_INVALID_PAGE_PROTECTION    ((DWORD)0xC0000045L)
#define STATUS_NO_MEMORY                  ((DWORD)0xC0000017L)
#define STATUS_ILLEGAL_INSTRUCTION        ((DWORD)0xC000001DL)
#define STATUS_NONCONTINUABLE_EXCEPTION   ((DWORD)0xC0000025L)
#define STATUS_INVALID_DISPOSITION        ((DWORD)0xC0000026L)
#define STATUS_OBJECT_NAME_COLLISION      ((DWORD)0xC0000035L)
#define STATUS_ARRAY_BOUNDS_EXCEEDED      ((DWORD)0xC000008CL)
#define STATUS_FLOAT_DENORMAL_OPERAND     ((DWORD)0xC000008DL)
#define STATUS_FLOAT_DIVIDE_BY_ZERO       ((DWORD)0xC000008EL)
#define STATUS_FLOAT_INEXACT_RESULT       ((DWORD)0xC000008FL)
#define STATUS_FLOAT_INVALID_OPERATION    ((DWORD)0xC0000090L)
#define STATUS_FLOAT_OVERFLOW             ((DWORD)0xC0000091L)
#define STATUS_FLOAT_STACK_CHECK          ((DWORD)0xC0000092L)
#define STATUS_FLOAT_UNDERFLOW            ((DWORD)0xC0000093L)
#define STATUS_INTEGER_DIVIDE_BY_ZERO     ((DWORD)0xC0000094L)
#define STATUS_INTEGER_OVERFLOW           ((DWORD)0xC0000095L)
#define STATUS_PRIVILEGED_INSTRUCTION     ((DWORD)0xC0000096L)
#define STATUS_FILE_IS_A_DIRECTORY        ((DWORD)0xC00000BAL)
#define STATUS_STACK_OVERFLOW             ((DWORD)0xC00000FDL)
#define STATUS_NAME_TOO_LONG              ((DWORD)0xC0000106L)
#define STATUS_DLL_NOT_FOUND              ((DWORD)0xC0000135L)
#define STATUS_ORDINAL_NOT_FOUND          ((DWORD)0xC0000138L)
#define STATUS_ENTRYPOINT_NOT_FOUND       ((DWORD)0xC0000139L)
#define STATUS_CONTROL_C_EXIT             ((DWORD)0xC000013AL)
#define STATUS_DLL_INIT_FAILED            ((DWORD)0xC0000142L)
#define STATUS_CONTROL_STACK_VIOLATION    ((DWORD)0xC00001B2L)
#define STATUS_FLOAT_MULTIPLE_FAULTS      ((DWORD)0xC00002B4L)
#define STATUS_FLOAT_MULTIPLE_TRAPS       ((DWORD)0xC00002B5L)
#define STATUS_REG_NAT_CONSUMPTION        ((DWORD)0xC00002C9L)
#define STATUS_HEAP_CORRUPTION            ((DWORD)0xC0000374L)
#define STATUS_STACK_BUFFER_OVERRUN       ((DWORD)0xC0000409L)
#define STATUS_INVALID_CRUNTIME_PARAMETER ((DWORD)0xC0000417L)
#define STATUS_ASSERTION_FAILURE          ((DWORD)0xC0000420L)
#define STATUS_ENCLAVE_VIOLATION          ((DWORD)0xC00004A2L)
#define STATUS_INTERRUPTED                ((DWORD)0xC0000515L)
#define STATUS_THREAD_NOT_RUNNING         ((DWORD)0xC0000516L)
#define STATUS_ALREADY_REGISTERED         ((DWORD)0xC0000718L)

#define MAXIMUM_WAIT_OBJECTS 64
#define MAXIMUM_SUSPEND_COUNT MAXCHAR

#ifndef NULL
#define NULL 0
#endif
#define bool  _Bool
#define false 0
#define true  1
#define FALSE 0
#define TRUE 1

#define TH32CS_INHERIT 0x80000000
#define TH32CS_SNAPHEAPLIST 0x00000001
#define TH32CS_SNAPMODULE 0x00000008
#define TH32CS_SNAPMODULE32 0x00000010
#define TH32CS_SNAPPROCESS 0x00000002
#define TH32CS_SNAPTHREAD 0x00000004
#define TH32CS_SNAPALL TH32CS_SNAPHEAPLIST | TH32CS_SNAPMODULE | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD

#define DELETE                            (0x00010000L)
#define READ_CONTROL                      (0x00020000L)
#define WRITE_DAC                         (0x00040000L)
#define WRITE_OWNER                       (0x00080000L)
#define SYNCHRONIZE                       (0x00100000L)
#define STANDARD_RIGHTS_REQUIRED          (0x000F0000L)
#define STANDARD_RIGHTS_READ              (READ_CONTROL)
#define STANDARD_RIGHTS_WRITE             (READ_CONTROL)
#define STANDARD_RIGHTS_EXECUTE           (READ_CONTROL)
#define STANDARD_RIGHTS_ALL               (0x001F0000L)
#define SPECIFIC_RIGHTS_ALL               (0x0000FFFFL)
#define ACCESS_SYSTEM_SECURITY            (0x01000000L)
#define MAXIMUM_ALLOWED                   (0x02000000L)
#define GENERIC_READ                      (0x80000000L)
#define GENERIC_WRITE                     (0x40000000L)
#define GENERIC_EXECUTE                   (0x20000000L)
#define GENERIC_ALL                       (0x10000000L)

#define PAGE_NOACCESS                     0x01
#define PAGE_READONLY                     0x02
#define PAGE_READWRITE                    0x04
#define PAGE_WRITECOPY                    0x08
#define PAGE_EXECUTE                      0x10
#define PAGE_EXECUTE_READ                 0x20
#define PAGE_EXECUTE_READWRITE            0x40
#define PAGE_EXECUTE_WRITECOPY            0x80
#define PAGE_GUARD                        0x100
#define PAGE_NOCACHE                      0x200
#define PAGE_WRITECOMBINE                 0x400
#define PAGE_GRAPHICS_NOACCESS            0x0800
#define PAGE_GRAPHICS_READONLY            0x1000
#define PAGE_GRAPHICS_READWRITE           0x2000
#define PAGE_GRAPHICS_EXECUTE             0x4000
#define PAGE_GRAPHICS_EXECUTE_READ        0x8000
#define PAGE_GRAPHICS_EXECUTE_READWRITE   0x10000
#define PAGE_GRAPHICS_COHERENT            0x20000
#define PAGE_GRAPHICS_NOCACHE             0x40000
#define PAGE_ENCLAVE_THREAD_CONTROL       0x80000000
#define PAGE_REVERT_TO_FILE_MAP           0x80000000
#define PAGE_TARGETS_NO_UPDATE            0x40000000
#define PAGE_TARGETS_INVALID              0x40000000
#define PAGE_ENCLAVE_UNVALIDATED          0x20000000
#define PAGE_ENCLAVE_MASK                 0x10000000
#define PAGE_ENCLAVE_DECOMMIT             PAGE_ENCLAVE_MASK | 0)
#define PAGE_ENCLAVE_SS_FIRST             PAGE_ENCLAVE_MASK | 1)
#define PAGE_ENCLAVE_SS_REST              (PAGE_ENCLAVE_MASK | 2)
#define MEM_COMMIT                        0x00001000
#define MEM_RESERVE                       0x00002000
#define MEM_REPLACE_PLACEHOLDER           0x00004000
#define MEM_RESERVE_PLACEHOLDER           0x00040000
#define MEM_RESET                         0x00080000
#define MEM_TOP_DOWN                      0x00100000
#define MEM_WRITE_WATCH                   0x00200000
#define MEM_PHYSICAL                      0x00400000
#define MEM_ROTATE                        0x00800000
#define MEM_DIFFERENT_IMAGE_BASE_OK       0x00800000
#define MEM_RESET_UNDO                    0x01000000
#define MEM_LARGE_PAGES                   0x20000000
#define MEM_4MB_PAGES                     0x80000000
#define MEM_64K_PAGES                     (MEM_LARGE_PAGES | MEM_PHYSICAL)
#define MEM_UNMAP_WITH_TRANSIENT_BOOST    0x00000001
#define MEM_COALESCE_PLACEHOLDERS         0x00000001
#define MEM_PRESERVE_PLACEHOLDER          0x00000002
#define MEM_DECOMMIT                      0x00004000
#define MEM_RELEASE                       0x00008000
#define MEM_FREE                          0x00010000


#define NT_SUCCESS(Status) ((ULONG)(Status) == 0)
#define NT_INFORMATION(Status) ((ULONG)(Status) >> 30==1)
#define NT_WARNING(Status) ((ULONG)(Status) >> 30==2)
#define NT_ERROR(Status) ((ULONG)(Status) >> 30==3)
typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;
typedef DWORD ACCESS_MASK;
typedef ACCESS_MASK* PACCESS_MASK;
typedef struct _ULARGE_INTEGER
{
    union
    {
        struct
        {
            ULONG LowPart;
            ULONG HighPart;
        };
        UINT64 QuadPart;
    };
} ULARGE_INTEGER, * PULARGE_INTEGER;
typedef struct _LARGE_INTEGER
{
    union
    {
        struct
        {
            ULONG LowPart;
            LONG HighPart;
        };
        INT64 QuadPart;
    };
} LARGE_INTEGER, * PLARGE_INTEGER;



typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink;
} LIST_ENTRY, * PLIST_ENTRY;
typedef struct _CLIENT_ID
{
    VOID* UniqueProcess;
    VOID* UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _UNICODE_STRING {
    unsigned short    Length;
    unsigned short    MaximumLength;
    wchar_t* Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _ACTIVATION_CONTEXT
{
    unsigned long       magic;
    int                 ref_count;
    //struct file_info    config;
    //struct file_info    appdir;
    struct assembly* assemblies;
    unsigned int        num_assemblies;
    unsigned int        allocated_assemblies;
    /* section data */
    unsigned long       sections;
    struct strsection_header* wndclass_section;
    struct strsection_header* dllredirect_section;
    struct strsection_header* progid_section;
    struct guidsection_header* tlib_section;
    struct guidsection_header* comserver_section;
    struct guidsection_header* ifaceps_section;
    struct guidsection_header* clrsurrogate_section;
} ACTIVATION_CONTEXT;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY            InLoadOrderLinks;                /* 0x00 */
    LIST_ENTRY            InMemoryOrderLinks;                /* 0x10 */
    LIST_ENTRY            InInitializationOrderLinks;        /* 0x20 */
    void* DllBase;                        /* 0x30 */
    void* EntryPoint;                        /* 0x38 */
    unsigned long        SizeOfImage;                    /* 0x40 */
    UNICODE_STRING        FullDllName;                    /* 0x48 */
    UNICODE_STRING        BaseDllName;                    /* 0x58 */
    unsigned long Flags;
    unsigned short LoadCount;
    unsigned short TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            void* SectionPointer;
            unsigned long CheckSum;
        };
    };
    union
    {
        unsigned long TimeDateStamp;
        void* LoadedImports;
    };
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
    void* PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;                                                           //0x0
    UCHAR Initialized;                                                      //0x4
    VOID* SsHandle;                                                         //0x8
    struct _LIST_ENTRY InLoadOrderModuleList;                               //0x10
    struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x20
    struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x30
    VOID* EntryInProgress;                                                  //0x40
    UCHAR ShutdownInProgress;                                               //0x48
    VOID* ShutdownThreadId;                                                 //0x50
} PEB_LDR_DATA, * PPEB_LDR_DATA;
typedef struct _RTL_CRITICAL_SECTION_DEBUG
{
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION* CriticalSection;
    LIST_ENTRY ProcessLocksList;
    ULONG EntryCount;
    ULONG ContentionCount;
    ULONG Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareUSHORT;
} RTL_CRITICAL_SECTION_DEBUG, * PRTL_CRITICAL_SECTION_DEBUG;
typedef struct _RTL_CRITICAL_SECTION
{
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    PVOID OwningThread;
    PVOID LockSemaphore;
    ULONG SpinCount;
} RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;
typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    WORD Flags;
    WORD Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;
typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    PVOID Handle;
} CURDIR, * PCURDIR;
typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    PVOID ConsoleHandle;
    ULONG ConsoleFlags;
    PVOID StandardInput;
    PVOID StandardOutput;
    PVOID StandardError;
    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
    ULONG EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;
typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK* Next;
    ULONG Size;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;
struct _ASSEMBLY_STORAGE_MAP;
struct _ACTIVATION_CONTEXT_DATA;
struct _FLS_CALLBACK_INFO;
typedef struct _GUID {
    unsigned long  Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char  Data4[8];
} GUID;
typedef struct _HEAP_EXTENDED_ENTRY
{
    VOID* Reserved;                                                         //0x0
    union
    {
        struct
        {
            USHORT FunctionIndex;                                           //0x8
            USHORT ContextValue;                                            //0xa
        };
        ULONG InterceptorValue;                                             //0x8
    };
    USHORT UnusedBytesLength;                                               //0xc
    UCHAR EntryOffset;                                                      //0xe
    UCHAR ExtendedBlockSignature;                                           //0xf
} HEAP_EXTENDED_ENTRY, *PHEAP_EXTENDED_ENTRY;
typedef struct _HEAP_UNPACKED_ENTRY
{
    VOID* PreviousBlockPrivateData;                                         //0x0
    union
    {
        struct
        {
            USHORT Size;                                                    //0x8
            UCHAR Flags;                                                    //0xa
            UCHAR SmallTagIndex;                                            //0xb
        };
        struct
        {
            ULONG SubSegmentCode;                                           //0x8
            USHORT PreviousSize;                                            //0xc
            union
            {
                UCHAR SegmentOffset;                                        //0xe
                UCHAR LFHFlags;                                             //0xe
            };
            UCHAR UnusedBytes;                                              //0xf
        };
        ULONGLONG CompactHeader;                                            //0x8
    };
} HEAP_UNPACKED_ENTRY, *PHEAP_UNPACKED_ENTRY;
typedef struct _HEAP_ENTRY
{
    union
    {
        HEAP_UNPACKED_ENTRY UnpackedEntry;                          //0x0
        struct
        {
            VOID* PreviousBlockPrivateData;                                 //0x0
            union
            {
                struct
                {
                    USHORT Size;                                            //0x8
                    UCHAR Flags;                                            //0xa
                    UCHAR SmallTagIndex;                                    //0xb
                };
                struct
                {
                    ULONG SubSegmentCode;                                   //0x8
                    USHORT PreviousSize;                                    //0xc
                    union
                    {
                        UCHAR SegmentOffset;                                //0xe
                        UCHAR LFHFlags;                                     //0xe
                    };
                    UCHAR UnusedBytes;                                      //0xf
                };
                ULONGLONG CompactHeader;                                    //0x8
            };
        };
        HEAP_EXTENDED_ENTRY ExtendedEntry;                          //0x0
        struct
        {
            VOID* Reserved;                                                 //0x0
            union
            {
                struct
                {
                    USHORT FunctionIndex;                                   //0x8
                    USHORT ContextValue;                                    //0xa
                };
                ULONG InterceptorValue;                                     //0x8
            };
            USHORT UnusedBytesLength;                                       //0xc
            UCHAR EntryOffset;                                              //0xe
            UCHAR ExtendedBlockSignature;                                   //0xf
        };
        struct
        {
            VOID* ReservedForAlignment;                                     //0x0
            union
            {
                struct
                {
                    ULONG Code1;                                            //0x8
                    union
                    {
                        struct
                        {
                            USHORT Code2;                                   //0xc
                            UCHAR Code3;                                    //0xe
                            UCHAR Code4;                                    //0xf
                        };
                        ULONG Code234;                                      //0xc
                    };
                };
                ULONGLONG AgregateCode;                                     //0x8
            };
        };
    };
} HEAP_ENTRY, *PHEAP_ENTRY;
typedef struct _HEAP_SEGMENT
{
    HEAP_ENTRY Entry;                                               //0x0
    ULONG SegmentSignature;                                                 //0x10
    ULONG SegmentFlags;                                                     //0x14
    LIST_ENTRY SegmentListEntry;                                    //0x18
    struct _HEAP* Heap;                                                     //0x28
    VOID* BaseAddress;                                                      //0x30
    ULONG NumberOfPages;                                                    //0x38
    PHEAP_ENTRY FirstEntry;                                         //0x40
    PHEAP_ENTRY LastValidEntry;                                     //0x48
    ULONG NumberOfUnCommittedPages;                                         //0x50
    ULONG NumberOfUnCommittedRanges;                                        //0x54
    USHORT SegmentAllocatorBackTraceIndex;                                  //0x58
    USHORT Reserved;                                                        //0x5a
    LIST_ENTRY UCRSegmentList;                                      //0x60
} HEAP_SEGMENT, *PHEAP_SEGMENT;
typedef union _RTL_RUN_ONCE
{
    VOID* Ptr;                                                              //0x0
    ULONGLONG Value;                                                        //0x0
    ULONGLONG State : 2;                                                    //0x0
} RTL_RUN_ONCE, *PRTL_RUN_ONCE;
typedef struct _RTL_HEAP_MEMORY_LIMIT_DATA
{
    ULONGLONG CommitLimitBytes;                                             //0x0
    ULONGLONG CommitLimitFailureCode;                                       //0x8
    ULONGLONG MaxAllocationSizeBytes;                                       //0x10
    ULONGLONG AllocationLimitFailureCode;                                   //0x18
} RTL_HEAP_MEMORY_LIMIT_DATA, *PRTL_HEAP_MEMORY_LIMIT_DATA;
typedef struct _HEAP_COUNTERS
{
    ULONGLONG TotalMemoryReserved;                                          //0x0
    ULONGLONG TotalMemoryCommitted;                                         //0x8
    ULONGLONG TotalMemoryLargeUCR;                                          //0x10
    ULONGLONG TotalSizeInVirtualBlocks;                                     //0x18
    ULONG TotalSegments;                                                    //0x20
    ULONG TotalUCRs;                                                        //0x24
    ULONG CommittOps;                                                       //0x28
    ULONG DeCommitOps;                                                      //0x2c
    ULONG LockAcquires;                                                     //0x30
    ULONG LockCollisions;                                                   //0x34
    ULONG CommitRate;                                                       //0x38
    ULONG DecommittRate;                                                    //0x3c
    ULONG CommitFailures;                                                   //0x40
    ULONG InBlockCommitFailures;                                            //0x44
    ULONG PollIntervalCounter;                                              //0x48
    ULONG DecommitsSinceLastCheck;                                          //0x4c
    ULONG HeapPollInterval;                                                 //0x50
    ULONG AllocAndFreeOps;                                                  //0x54
    ULONG AllocationIndicesActive;                                          //0x58
    ULONG InBlockDeccommits;                                                //0x5c
    ULONGLONG InBlockDeccomitSize;                                          //0x60
    ULONGLONG HighWatermarkSize;                                            //0x68
    ULONGLONG LastPolledSize;                                               //0x70
} HEAP_COUNTERS, *PHEAP_COUNTERS;
typedef struct _HEAP_TUNING_PARAMETERS
{
    ULONG CommittThresholdShift;                                            //0x0
    ULONGLONG MaxPreCommittThreshold;                                       //0x8
} HEAP_TUNING_PARAMETERS, *PHEAP_TUNING_PARAMETERS;
typedef struct _HEAP_TAG_ENTRY
{
    ULONG Allocs;                                                           //0x0
    ULONG Frees;                                                            //0x4
    ULONGLONG Size;                                                         //0x8
    USHORT TagIndex;                                                        //0x10
    USHORT CreatorBackTraceIndex;                                           //0x12
    WCHAR TagName[24];                                                      //0x14
} HEAP_TAG_ENTRY, *PHEAP_TAG_ENTRY;
typedef struct _OWNER_ENTRY
{
    ULONGLONG OwnerThread;                                                  //0x0
    union
    {
        struct
        {
            ULONG IoPriorityBoosted : 1;                                      //0x8
            ULONG OwnerReferenced : 1;                                        //0x8
            ULONG IoQoSPriorityBoosted : 1;                                   //0x8
            ULONG OwnerCount : 29;                                            //0x8
        };
        ULONG TableSize;                                                    //0x8
    };
} OWNER_ENTRY, *POWNER_ENTRY;
typedef struct _ERESOURCE
{
    LIST_ENTRY SystemResourcesList;                                 //0x0
    OWNER_ENTRY* OwnerTable;                                        //0x10
    SHORT ActiveCount;                                                      //0x18
    union
    {
        USHORT Flag;                                                        //0x1a
        struct
        {
            UCHAR ReservedLowFlags;                                         //0x1a
            UCHAR WaiterPriority;                                           //0x1b
        };
    };
    VOID* SharedWaiters;                                                    //0x20
    VOID* ExclusiveWaiters;                                                 //0x28
    OWNER_ENTRY OwnerEntry;                                         //0x30
    ULONG ActiveEntries;                                                    //0x40
    ULONG ContentionCount;                                                  //0x44
    ULONG NumberOfSharedWaiters;                                            //0x48
    ULONG NumberOfExclusiveWaiters;                                         //0x4c
    VOID* Reserved2;                                                        //0x50
    union
    {
        VOID* Address;                                                      //0x58
        ULONGLONG CreatorBackTraceIndex;                                    //0x58
    };
    ULONGLONG SpinLock;                                                     //0x60
} ERESOURCE, *PERESOURCE;
typedef struct _HEAP_LOCK
{
    union
    {
        RTL_CRITICAL_SECTION CriticalSection;                       //0x0
        ERESOURCE Resource;                                         //0x0
    } Lock;                                                                 //0x0
} HEAP_LOCK, *PHEAP_LOCK;
typedef struct _HEAP_PSEUDO_TAG_ENTRY
{
    ULONG Allocs;                                                           //0x0
    ULONG Frees;                                                            //0x4
    ULONGLONG Size;                                                         //0x8
} HEAP_PSEUDO_TAG_ENTRY, *PHEAP_PSEUDO_TAG_ENTRY;
typedef struct _HEAP
{
    union
    {
        HEAP_SEGMENT Segment;                                       //0x0
        struct
        {
            HEAP_ENTRY Entry;                                       //0x0
            ULONG SegmentSignature;                                         //0x10
            ULONG SegmentFlags;                                             //0x14
            LIST_ENTRY SegmentListEntry;                            //0x18
            struct _HEAP* Heap;                                             //0x28
            VOID* BaseAddress;                                              //0x30
            ULONG NumberOfPages;                                            //0x38
            HEAP_ENTRY* FirstEntry;                                 //0x40
            HEAP_ENTRY* LastValidEntry;                             //0x48
            ULONG NumberOfUnCommittedPages;                                 //0x50
            ULONG NumberOfUnCommittedRanges;                                //0x54
            USHORT SegmentAllocatorBackTraceIndex;                          //0x58
            USHORT Reserved;                                                //0x5a
            LIST_ENTRY UCRSegmentList;                              //0x60
        };
    };
    ULONG Flags;                                                            //0x70
    ULONG ForceFlags;                                                       //0x74
    ULONG CompatibilityFlags;                                               //0x78
    ULONG EncodeFlagMask;                                                   //0x7c
    HEAP_ENTRY Encoding;                                            //0x80
    ULONG Interceptor;                                                      //0x90
    ULONG VirtualMemoryThreshold;                                           //0x94
    ULONG Signature;                                                        //0x98
    ULONGLONG SegmentReserve;                                               //0xa0
    ULONGLONG SegmentCommit;                                                //0xa8
    ULONGLONG DeCommitFreeBlockThreshold;                                   //0xb0
    ULONGLONG DeCommitTotalFreeThreshold;                                   //0xb8
    ULONGLONG TotalFreeSize;                                                //0xc0
    ULONGLONG MaximumAllocationSize;                                        //0xc8
    USHORT ProcessHeapsListIndex;                                           //0xd0
    USHORT HeaderValidateLength;                                            //0xd2
    VOID* HeaderValidateCopy;                                               //0xd8
    USHORT NextAvailableTagIndex;                                           //0xe0
    USHORT MaximumTagIndex;                                                 //0xe2
    HEAP_TAG_ENTRY* TagEntries;                                     //0xe8
    LIST_ENTRY UCRList;                                             //0xf0
    ULONGLONG AlignRound;                                                   //0x100
    ULONGLONG AlignMask;                                                    //0x108
    LIST_ENTRY VirtualAllocdBlocks;                                 //0x110
    LIST_ENTRY SegmentList;                                         //0x120
    USHORT AllocatorBackTraceIndex;                                         //0x130
    ULONG NonDedicatedListLength;                                           //0x134
    VOID* BlocksIndex;                                                      //0x138
    VOID* UCRIndex;                                                         //0x140
    struct _HEAP_PSEUDO_TAG_ENTRY* PseudoTagEntries;                        //0x148
    LIST_ENTRY FreeLists;                                           //0x150
    HEAP_LOCK* LockVariable;                                        //0x160
    LONG(*CommitRoutine)(VOID* arg1, VOID** arg2, ULONGLONG* arg3);        //0x168
    RTL_RUN_ONCE StackTraceInitVar;                                  //0x170
    RTL_HEAP_MEMORY_LIMIT_DATA CommitLimitData;                     //0x178
    VOID* FrontEndHeap;                                                     //0x198
    USHORT FrontHeapLockCount;                                              //0x1a0
    UCHAR FrontEndHeapType;                                                 //0x1a2
    UCHAR RequestedFrontEndHeapType;                                        //0x1a3
    WCHAR* FrontEndHeapUsageData;                                           //0x1a8
    USHORT FrontEndHeapMaximumIndex;                                        //0x1b0
    volatile UCHAR FrontEndHeapStatusBitmap[129];                           //0x1b2
    HEAP_COUNTERS Counters;                                         //0x238
    HEAP_TUNING_PARAMETERS TuningParameters;                        //0x2b0
} HEAP, *PHEAP;
typedef struct _PEB
{
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
     union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages:1;                                    //0x3
            UCHAR IsProtectedProcess:1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated:1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders:1;                           //0x3
            UCHAR IsPackagedProcess:1;                                      //0x3
            UCHAR IsAppContainer:1;                                         //0x3
            UCHAR IsProtectedProcessLight:1;                                //0x3
            UCHAR IsLongPathAwareProcess:1;                                 //0x3
        };
    };
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PHEAP ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    union
    {
        ULONG CrossProcessFlags;                                            //0x28
        struct
        {
            ULONG ProcessInJob : 1;                                           //0x28
            ULONG ProcessInitializing : 1;                                    //0x28
            ULONG ProcessUsingVEH : 1;                                        //0x28
            ULONG ProcessUsingVCH : 1;                                        //0x28
            ULONG ProcessUsingFTH : 1;                                        //0x28
            ULONG ProcessPreviouslyThrottled : 1;                             //0x28
            ULONG ProcessCurrentlyThrottled : 1;                              //0x28
            ULONG ProcessImagesHotPatched : 1;                                //0x28
            ULONG ReservedBits0 : 24;                                         //0x28
        };
    };
    union
    {
        VOID* KernelCallbackTable;                                          //0x2c
        VOID* UserSharedInfoPtr;                                            //0x2c
    };
    ULONG SystemReserved[1];
    ULONG SpareUlong;
    PPEB_FREE_BLOCK FreeList;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID HotpatchInformation;
    VOID** ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    ULONG HeapSegmentReserve;
    ULONG HeapSegmentCommit;
    ULONG HeapDeCommitTotalFreeThreshold;
    ULONG HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    VOID** ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    PRTL_CRITICAL_SECTION LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    WORD OSBuildNumber;
    WORD OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG ImageProcessAffinityMask;
    ULONG GdiHandleBuffer[34];
    PVOID PostProcessInitRoutine;
    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];
    ULONG SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo;
    UNICODE_STRING CSDVersion;
    struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;
    struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;
    struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;
    struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;
    ULONG MinimumStackCommit;
    struct _FLS_CALLBACK_INFO* FlsCallback;
    LIST_ENTRY FlsListHead;
    PVOID FlsBitmap;
    ULONG FlsBitmapBits[4];
    ULONG FlsHighIndex;
    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
} PEB, * PPEB;
struct _NT_TIB
{
    struct _EXCEPTION_REGISTRATION_RECORD* ExceptionList;                   //0x0
    VOID* StackBase;                                                        //0x8
    VOID* StackLimit;                                                       //0x10
    VOID* SubSystemTib;                                                     //0x18
    union
    {
        VOID* FiberData;                                                    //0x20
        ULONG Version;                                                      //0x20
    };
    VOID* ArbitraryUserPointer;                                             //0x28
    struct _NT_TIB* Self;                                                   //0x30
};
typedef struct _FLOATING_SAVE_AREA {
    DWORD   ControlWord;
    DWORD   StatusWord;
    DWORD   TagWord;
    DWORD   ErrorOffset;
    DWORD   ErrorSelector;
    DWORD   DataOffset;
    DWORD   DataSelector;
    BYTE    RegisterArea[SIZE_OF_80387_REGISTERS];
    DWORD   Spare0;
} FLOATING_SAVE_AREA;
#define CONTEXT_i386    0x00010000L    // this assumes that i386 and
#define CONTEXT_i486    0x00010000L    // i486 have identical context records
#define CONTEXT_CONTROL         (CONTEXT_i386 | 0x00000001L) // SS:SP, CS:IP, FLAGS, BP
#define CONTEXT_INTEGER         (CONTEXT_i386 | 0x00000002L) // AX, BX, CX, DX, SI, DI
#define CONTEXT_SEGMENTS        (CONTEXT_i386 | 0x00000004L) // DS, ES, FS, GS
#define CONTEXT_FLOATING_POINT  (CONTEXT_i386 | 0x00000008L) // 387 state
#define CONTEXT_DEBUG_REGISTERS (CONTEXT_i386 | 0x00000010L) // DB 0-3,6,7
#define CONTEXT_EXTENDED_REGISTERS  (CONTEXT_i386 | 0x00000020L) // cpu specific extensions

#define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_INTEGER |\
                      CONTEXT_SEGMENTS)

#define CONTEXT_ALL             (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | \
                                 CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | \
                                 CONTEXT_EXTENDED_REGISTERS)

#define CONTEXT_XSTATE          (CONTEXT_i386 | 0x00000040L)

#define CONTEXT_EXCEPTION_ACTIVE    0x08000000L
#define CONTEXT_SERVICE_ACTIVE      0x10000000L
#define CONTEXT_EXCEPTION_REQUEST   0x40000000L
#define CONTEXT_EXCEPTION_REPORTING 0x80000000L

typedef struct _CONTEXT {
    DWORD ContextFlags;
    DWORD   Dr0;
    DWORD   Dr1;
    DWORD   Dr2;
    DWORD   Dr3;
    DWORD   Dr6;
    DWORD   Dr7;
    FLOATING_SAVE_AREA FloatSave;
    DWORD   SegGs;
    DWORD   SegFs;
    DWORD   SegEs;
    DWORD   SegDs;
    DWORD   Edi;
    DWORD   Esi;
    DWORD   Ebx;
    DWORD   Edx;
    DWORD   Ecx;
    DWORD   Eax;
    DWORD   Ebp;
    DWORD   Eip;
    DWORD   SegCs;              // MUST BE SANITIZED
    DWORD   EFlags;             // MUST BE SANITIZED
    DWORD   Esp;
    DWORD   SegSs;

    BYTE    ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];
} CONTEXT, *PCONTEXT;
struct _GDI_TEB_BATCH
{
    ULONG Offset : 31;                                                        //0x0
    ULONG HasRenderingCommand : 1;                                            //0x0
    ULONGLONG HDC;                                                          //0x8
    ULONG Buffer[310];                                                      //0x10
};
typedef struct _PROCESSOR_NUMBER {
    WORD   Group;
    BYTE  Number;
    BYTE  Reserved;
} PROCESSOR_NUMBER, * PPROCESSOR_NUMBER;
//0x1838 bytes (sizeof)
typedef struct _TEB
{
    struct _NT_TIB NtTib;                                                   //0x0
    VOID* EnvironmentPointer;                                               //0x38
    CLIENT_ID ClientId;                                                     //0x40
    VOID* ActiveRpcHandle;                                                  //0x50
    VOID* ThreadLocalStoragePointer;                                        //0x58
    struct _PEB* ProcessEnvironmentBlock;                                   //0x60
    ULONG LastErrorValue;                                                   //0x68
    ULONG CountOfOwnedCriticalSections;                                     //0x6c
    VOID* CsrClientThread;                                                  //0x70
    VOID* Win32ThreadInfo;                                                  //0x78
    ULONG User32Reserved[26];                                               //0x80
    ULONG UserReserved[5];                                                  //0xe8
    VOID* WOW32Reserved;                                                    //0x100
    ULONG CurrentLocale;                                                    //0x108
    ULONG FpSoftwareStatusRegister;                                         //0x10c
    VOID* ReservedForDebuggerInstrumentation[16];                           //0x110
    VOID* SystemReserved1[38];                                              //0x190
    LONG ExceptionCode;                                                     //0x2c0
    UCHAR Padding0[4];                                                      //0x2c4
    struct _ACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;        //0x2c8
    ULONGLONG InstrumentationCallbackSp;                                    //0x2d0
    ULONGLONG InstrumentationCallbackPreviousPc;                            //0x2d8
    ULONGLONG InstrumentationCallbackPreviousSp;                            //0x2e0
    ULONG TxFsContext;                                                      //0x2e8
    UCHAR InstrumentationCallbackDisabled;                                  //0x2ec
    UCHAR Padding1[3];                                                      //0x2ed
    struct _GDI_TEB_BATCH GdiTebBatch;                                      //0x2f0
    CLIENT_ID RealClientId;                                                 //0x7d8
    VOID* GdiCachedProcessHandle;                                           //0x7e8
    ULONG GdiClientPID;                                                     //0x7f0
    ULONG GdiClientTID;                                                     //0x7f4
    VOID* GdiThreadLocalInfo;                                               //0x7f8
    ULONGLONG Win32ClientInfo[62];                                          //0x800
    VOID* glDispatchTable[233];                                             //0x9f0
    ULONGLONG glReserved1[29];                                              //0x1138
    VOID* glReserved2;                                                      //0x1220
    VOID* glSectionInfo;                                                    //0x1228
    VOID* glSection;                                                        //0x1230
    VOID* glTable;                                                          //0x1238
    VOID* glCurrentRC;                                                      //0x1240
    VOID* glContext;                                                        //0x1248
    ULONG LastStatusValue;                                                  //0x1250
    UCHAR Padding2[4];                                                      //0x1254
    struct _UNICODE_STRING StaticUnicodeString;                             //0x1258
    WCHAR StaticUnicodeBuffer[261];                                         //0x1268
    UCHAR Padding3[6];                                                      //0x1472
    VOID* DeallocationStack;                                                //0x1478
    VOID* TlsSlots[64];                                                     //0x1480
    struct _LIST_ENTRY TlsLinks;                                            //0x1680
    VOID* Vdm;                                                              //0x1690
    VOID* ReservedForNtRpc;                                                 //0x1698
    VOID* DbgSsReserved[2];                                                 //0x16a0
    ULONG HardErrorMode;                                                    //0x16b0
    UCHAR Padding4[4];                                                      //0x16b4
    VOID* Instrumentation[11];                                              //0x16b8
    struct _GUID ActivityId;                                                //0x1710
    VOID* SubProcessTag;                                                    //0x1720
    VOID* PerflibData;                                                      //0x1728
    VOID* EtwTraceData;                                                     //0x1730
    VOID* WinSockData;                                                      //0x1738
    ULONG GdiBatchCount;                                                    //0x1740
    union
    {
        struct _PROCESSOR_NUMBER CurrentIdealProcessor;                     //0x1744
        ULONG IdealProcessorValue;                                          //0x1744
        struct
        {
            UCHAR ReservedPad0;                                             //0x1744
            UCHAR ReservedPad1;                                             //0x1745
            UCHAR ReservedPad2;                                             //0x1746
            UCHAR IdealProcessor;                                           //0x1747
        };
    };
    ULONG GuaranteedStackBytes;                                             //0x1748
    UCHAR Padding5[4];                                                      //0x174c
    VOID* ReservedForPerf;                                                  //0x1750
    VOID* ReservedForOle;                                                   //0x1758
    ULONG WaitingOnLoaderLock;                                              //0x1760
    UCHAR Padding6[4];                                                      //0x1764
    VOID* SavedPriorityState;                                               //0x1768
    ULONGLONG ReservedForCodeCoverage;                                      //0x1770
    VOID* ThreadPoolData;                                                   //0x1778
    VOID** TlsExpansionSlots;                                               //0x1780
    VOID* DeallocationBStore;                                               //0x1788
    VOID* BStoreLimit;                                                      //0x1790
    ULONG MuiGeneration;                                                    //0x1798
    ULONG IsImpersonating;                                                  //0x179c
    VOID* NlsCache;                                                         //0x17a0
    VOID* pShimData;                                                        //0x17a8
    USHORT HeapVirtualAffinity;                                             //0x17b0
    USHORT LowFragHeapDataSlot;                                             //0x17b2
    UCHAR Padding7[4];                                                      //0x17b4
    VOID* CurrentTransactionHandle;                                         //0x17b8
    struct _TEB_ACTIVE_FRAME* ActiveFrame;                                  //0x17c0
    VOID* FlsData;                                                          //0x17c8
    VOID* PreferredLanguages;                                               //0x17d0
    VOID* UserPrefLanguages;                                                //0x17d8
    VOID* MergedPrefLanguages;                                              //0x17e0
    ULONG MuiImpersonation;                                                 //0x17e8
    union
    {
        volatile USHORT CrossTebFlags;                                      //0x17ec
        USHORT SpareCrossTebBits : 16;                                        //0x17ec
    };
    union
    {
        USHORT SameTebFlags;                                                //0x17ee
        struct
        {
            USHORT SafeThunkCall : 1;                                         //0x17ee
            USHORT InDebugPrint : 1;                                          //0x17ee
            USHORT HasFiberData : 1;                                          //0x17ee
            USHORT SkipThreadAttach : 1;                                      //0x17ee
            USHORT WerInShipAssertCode : 1;                                   //0x17ee
            USHORT RanProcessInit : 1;                                        //0x17ee
            USHORT ClonedThread : 1;                                          //0x17ee
            USHORT SuppressDebugMsg : 1;                                      //0x17ee
            USHORT DisableUserStackWalk : 1;                                  //0x17ee
            USHORT RtlExceptionAttached : 1;                                  //0x17ee
            USHORT InitialThread : 1;                                         //0x17ee
            USHORT SessionAware : 1;                                          //0x17ee
            USHORT LoadOwner : 1;                                             //0x17ee
            USHORT LoaderWorker : 1;                                          //0x17ee
            USHORT SpareSameTebBits : 2;                                      //0x17ee
        };
    };
    VOID* TxnScopeEnterCallback;                                            //0x17f0
    VOID* TxnScopeExitCallback;                                             //0x17f8
    VOID* TxnScopeContext;                                                  //0x1800
    ULONG LockCount;                                                        //0x1808
    LONG WowTebOffset;                                                      //0x180c
    VOID* ResourceRetValue;                                                 //0x1810
    VOID* ReservedForWdf;                                                   //0x1818
    ULONGLONG ReservedForCrt;                                               //0x1820
    struct _GUID EffectiveContainerId;                                      //0x1828
} TEB, *PTEB;

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_OS2_HEADER {      // OS/2 .EXE header
    WORD   ne_magic;                    // Magic number
    CHAR   ne_ver;                      // Version number
    CHAR   ne_rev;                      // Revision number
    WORD   ne_enttab;                   // Offset of Entry Table
    WORD   ne_cbenttab;                 // Number of bytes in Entry Table
    LONG   ne_crc;                      // Checksum of whole file
    WORD   ne_flags;                    // Flag word
    WORD   ne_autodata;                 // Automatic data segment number
    WORD   ne_heap;                     // Initial heap allocation
    WORD   ne_stack;                    // Initial stack allocation
    LONG   ne_csip;                     // Initial CS:IP setting
    LONG   ne_sssp;                     // Initial SS:SP setting
    WORD   ne_cseg;                     // Count of file segments
    WORD   ne_cmod;                     // Entries in Module Reference Table
    WORD   ne_cbnrestab;                // Size of non-resident name table
    WORD   ne_segtab;                   // Offset of Segment Table
    WORD   ne_rsrctab;                  // Offset of Resource Table
    WORD   ne_restab;                   // Offset of resident name table
    WORD   ne_modtab;                   // Offset of Module Reference Table
    WORD   ne_imptab;                   // Offset of Imported Names Table
    LONG   ne_nrestab;                  // Offset of Non-resident Names Table
    WORD   ne_cmovent;                  // Count of movable entries
    WORD   ne_align;                    // Segment alignment shift count
    WORD   ne_cres;                     // Count of resource segments
    BYTE   ne_exetyp;                   // Target Operating system
    BYTE   ne_flagsothers;              // Other .EXE flags
    WORD   ne_pretthunks;               // offset to return thunks
    WORD   ne_psegrefbytes;             // offset to segment ref. bytes
    WORD   ne_swaparea;                 // Minimum code swap area size
    WORD   ne_expver;                   // Expected Windows version number
} IMAGE_OS2_HEADER, * PIMAGE_OS2_HEADER;

typedef struct _IMAGE_VXD_HEADER {      // Windows VXD header
    WORD   e32_magic;                   // Magic number
    BYTE   e32_border;                  // The byte ordering for the VXD
    BYTE   e32_worder;                  // The word ordering for the VXD
    DWORD  e32_level;                   // The EXE format level for now = 0
    WORD   e32_cpu;                     // The CPU type
    WORD   e32_os;                      // The OS type
    DWORD  e32_ver;                     // Module version
    DWORD  e32_mflags;                  // Module flags
    DWORD  e32_mpages;                  // Module # pages
    DWORD  e32_startobj;                // Object # for instruction pointer
    DWORD  e32_eip;                     // Extended instruction pointer
    DWORD  e32_stackobj;                // Object # for stack pointer
    DWORD  e32_esp;                     // Extended stack pointer
    DWORD  e32_pagesize;                // VXD page size
    DWORD  e32_lastpagesize;            // Last page size in VXD
    DWORD  e32_fixupsize;               // Fixup section size
    DWORD  e32_fixupsum;                // Fixup section checksum
    DWORD  e32_ldrsize;                 // Loader section size
    DWORD  e32_ldrsum;                  // Loader section checksum
    DWORD  e32_objtab;                  // Object table offset
    DWORD  e32_objcnt;                  // Number of objects in module
    DWORD  e32_objmap;                  // Object page map offset
    DWORD  e32_itermap;                 // Object iterated data map offset
    DWORD  e32_rsrctab;                 // Offset of Resource Table
    DWORD  e32_rsrccnt;                 // Number of resource entries
    DWORD  e32_restab;                  // Offset of resident name table
    DWORD  e32_enttab;                  // Offset of Entry Table
    DWORD  e32_dirtab;                  // Offset of Module Directive Table
    DWORD  e32_dircnt;                  // Number of module directives
    DWORD  e32_fpagetab;                // Offset of Fixup Page Table
    DWORD  e32_frectab;                 // Offset of Fixup Record Table
    DWORD  e32_impmod;                  // Offset of Import Module Name Table
    DWORD  e32_impmodcnt;               // Number of entries in Import Module Name Table
    DWORD  e32_impproc;                 // Offset of Import Procedure Name Table
    DWORD  e32_pagesum;                 // Offset of Per-Page Checksum Table
    DWORD  e32_datapage;                // Offset of Enumerated Data Pages
    DWORD  e32_preload;                 // Number of preload pages
    DWORD  e32_nrestab;                 // Offset of Non-resident Names Table
    DWORD  e32_cbnrestab;               // Size of Non-resident Name Table
    DWORD  e32_nressum;                 // Non-resident Name Table Checksum
    DWORD  e32_autodata;                // Object # for automatic data object
    DWORD  e32_debuginfo;               // Offset of the debugging information
    DWORD  e32_debuglen;                // The length of the debugging info. in bytes
    DWORD  e32_instpreload;             // Number of instance pages in preload section of VXD file
    DWORD  e32_instdemand;              // Number of instance pages in demand load section of VXD file
    DWORD  e32_heapsize;                // Size of heap - for 16-bit apps
    BYTE   e32_res3[12];                // Reserved words
    DWORD  e32_winresoff;
    DWORD  e32_winreslen;
    WORD   e32_devid;                   // Device ID for VxD
    WORD   e32_ddkver;                  // DDK version for VxD
} IMAGE_VXD_HEADER, * PIMAGE_VXD_HEADER;


//
// File header format.
//

typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

#define IMAGE_SIZEOF_FILE_HEADER             20

#define IMAGE_FILE_RELOCS_STRIPPED           0x0001  // Relocation info stripped from file.
#define IMAGE_FILE_EXECUTABLE_IMAGE          0x0002  // File is executable  (i.e. no unresolved external references).
#define IMAGE_FILE_LINE_NUMS_STRIPPED        0x0004  // Line numbers stripped from file.
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED       0x0008  // Local symbols stripped from file.
#define IMAGE_FILE_AGGRESIVE_WS_TRIM         0x0010  // Aggressively trim working set
#define IMAGE_FILE_LARGE_ADDRESS_AWARE       0x0020  // App can handle >2gb addresses
#define IMAGE_FILE_BYTES_REVERSED_LO         0x0080  // Bytes of machine word are reversed.
#define IMAGE_FILE_32BIT_MACHINE             0x0100  // 32 bit word machine.
#define IMAGE_FILE_DEBUG_STRIPPED            0x0200  // Debugging info stripped from file in .DBG file
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP   0x0400  // If Image is on removable media, copy and run from the swap file.
#define IMAGE_FILE_NET_RUN_FROM_SWAP         0x0800  // If Image is on Net, copy and run from the swap file.
#define IMAGE_FILE_SYSTEM                    0x1000  // System File.
#define IMAGE_FILE_DLL                       0x2000  // File is a DLL.
#define IMAGE_FILE_UP_SYSTEM_ONLY            0x4000  // File should only be run on a UP machine
#define IMAGE_FILE_BYTES_REVERSED_HI         0x8000  // Bytes of machine word are reversed.

#define IMAGE_FILE_MACHINE_UNKNOWN           0
#define IMAGE_FILE_MACHINE_TARGET_HOST       0x0001  // Useful for indicating we want to interact with the host and not a WoW guest.
#define IMAGE_FILE_MACHINE_I386              0x014c  // Intel 386.
#define IMAGE_FILE_MACHINE_R3000             0x0162  // MIPS little-endian, 0x160 big-endian
#define IMAGE_FILE_MACHINE_R4000             0x0166  // MIPS little-endian
#define IMAGE_FILE_MACHINE_R10000            0x0168  // MIPS little-endian
#define IMAGE_FILE_MACHINE_WCEMIPSV2         0x0169  // MIPS little-endian WCE v2
#define IMAGE_FILE_MACHINE_ALPHA             0x0184  // Alpha_AXP
#define IMAGE_FILE_MACHINE_SH3               0x01a2  // SH3 little-endian
#define IMAGE_FILE_MACHINE_SH3DSP            0x01a3
#define IMAGE_FILE_MACHINE_SH3E              0x01a4  // SH3E little-endian
#define IMAGE_FILE_MACHINE_SH4               0x01a6  // SH4 little-endian
#define IMAGE_FILE_MACHINE_SH5               0x01a8  // SH5
#define IMAGE_FILE_MACHINE_ARM               0x01c0  // ARM Little-Endian
#define IMAGE_FILE_MACHINE_THUMB             0x01c2  // ARM Thumb/Thumb-2 Little-Endian
#define IMAGE_FILE_MACHINE_ARMNT             0x01c4  // ARM Thumb-2 Little-Endian
#define IMAGE_FILE_MACHINE_AM33              0x01d3
#define IMAGE_FILE_MACHINE_POWERPC           0x01F0  // IBM PowerPC Little-Endian
#define IMAGE_FILE_MACHINE_POWERPCFP         0x01f1
#define IMAGE_FILE_MACHINE_IA64              0x0200  // Intel 64
#define IMAGE_FILE_MACHINE_MIPS16            0x0266  // MIPS
#define IMAGE_FILE_MACHINE_ALPHA64           0x0284  // ALPHA64
#define IMAGE_FILE_MACHINE_MIPSFPU           0x0366  // MIPS
#define IMAGE_FILE_MACHINE_MIPSFPU16         0x0466  // MIPS
#define IMAGE_FILE_MACHINE_AXP64             IMAGE_FILE_MACHINE_ALPHA64
#define IMAGE_FILE_MACHINE_TRICORE           0x0520  // Infineon
#define IMAGE_FILE_MACHINE_CEF               0x0CEF
#define IMAGE_FILE_MACHINE_EBC               0x0EBC  // EFI Byte Code
#define IMAGE_FILE_MACHINE_AMD64             0x8664  // AMD64 (K8)
#define IMAGE_FILE_MACHINE_M32R              0x9041  // M32R little-endian
#define IMAGE_FILE_MACHINE_ARM64             0xAA64  // ARM64 Little-Endian
#define IMAGE_FILE_MACHINE_CEE               0xC0EE


//
// Directory format.
//

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

//
// Optional header format.
//

typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //

    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;

    //
    // NT additional fields.
    //

    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_ROM_OPTIONAL_HEADER {
    WORD   Magic;
    BYTE   MajorLinkerVersion;
    BYTE   MinorLinkerVersion;
    DWORD  SizeOfCode;
    DWORD  SizeOfInitializedData;
    DWORD  SizeOfUninitializedData;
    DWORD  AddressOfEntryPoint;
    DWORD  BaseOfCode;
    DWORD  BaseOfData;
    DWORD  BaseOfBss;
    DWORD  GprMask;
    DWORD  CprMask[4];
    DWORD  GpValue;
} IMAGE_ROM_OPTIONAL_HEADER, * PIMAGE_ROM_OPTIONAL_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b
#define IMAGE_ROM_OPTIONAL_HDR_MAGIC       0x107

#ifdef _WIN64
typedef IMAGE_OPTIONAL_HEADER64             IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER64            PIMAGE_OPTIONAL_HEADER;
#define IMAGE_NT_OPTIONAL_HDR_MAGIC         IMAGE_NT_OPTIONAL_HDR64_MAGIC
#else
typedef IMAGE_OPTIONAL_HEADER32             IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER32            PIMAGE_OPTIONAL_HEADER;
#define IMAGE_NT_OPTIONAL_HDR_MAGIC         IMAGE_NT_OPTIONAL_HDR32_MAGIC
#endif

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, * PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_ROM_HEADERS {
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_ROM_OPTIONAL_HEADER OptionalHeader;
} IMAGE_ROM_HEADERS, * PIMAGE_ROM_HEADERS;

#define OBJ_INHERIT                             0x00000002L
#define OBJ_PERMANENT                           0x00000010L
#define OBJ_EXCLUSIVE                           0x00000020L
#define OBJ_CASE_INSENSITIVE                    0x00000040L
#define OBJ_OPENIF                              0x00000080L
#define OBJ_OPENLINK                            0x00000100L
#define OBJ_KERNEL_HANDLE                       0x00000200L
#define OBJ_FORCE_ACCESS_CHECK                  0x00000400L
#define OBJ_VALID_ATTRIBUTES                    0x000007F2L

#define InitializeObjectAttributes(p,n,a,r,s) do { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);    \
    (p)->RootDirectory = (r);                   \
    (p)->Attributes = (a);                      \
    (p)->ObjectName = (n);                      \
    (p)->SecurityDescriptor = (s);              \
    (p)->SecurityQualityOfService = NULL;       \
} while(0)
typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#ifdef _WIN64
typedef IMAGE_NT_HEADERS64                  IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS64                 PIMAGE_NT_HEADERS;
#else
typedef IMAGE_NT_HEADERS32                  IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS32                 PIMAGE_NT_HEADERS;
#endif

// IMAGE_FIRST_SECTION doesn't need 32/64 versions since the file header is the same either way.

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

#define IMAGE_SUBSYSTEM_UNKNOWN              0   // Unknown subsystem.
#define IMAGE_SUBSYSTEM_NATIVE               1   // Image doesn't require a subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_GUI          2   // Image runs in the Windows GUI subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_CUI          3   // Image runs in the Windows character subsystem.
#define IMAGE_SUBSYSTEM_OS2_CUI              5   // image runs in the OS/2 character subsystem.
#define IMAGE_SUBSYSTEM_POSIX_CUI            7   // image runs in the Posix character subsystem.
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS       8   // image is a native Win9x driver.
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI       9   // Image runs in the Windows CE subsystem.
#define IMAGE_SUBSYSTEM_EFI_APPLICATION      10  //
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  11   //
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER   12  //
#define IMAGE_SUBSYSTEM_EFI_ROM              13
#define IMAGE_SUBSYSTEM_XBOX                 14
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16
#define IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG    17

// DllCharacteristics Entries

//      IMAGE_LIBRARY_PROCESS_INIT            0x0001     // Reserved.
//      IMAGE_LIBRARY_PROCESS_TERM            0x0002     // Reserved.
//      IMAGE_LIBRARY_THREAD_INIT             0x0004     // Reserved.
//      IMAGE_LIBRARY_THREAD_TERM             0x0008     // Reserved.
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA    0x0020  // Image can handle a high entropy 64-bit virtual address space.
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040     // DLL can move.
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY    0x0080     // Code Integrity Image
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT    0x0100     // Image is NX compatible
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION 0x0200     // Image understands isolation and doesn't want it
#define IMAGE_DLLCHARACTERISTICS_NO_SEH       0x0400     // Image does not use SEH.  No SE handler may reside in this image
#define IMAGE_DLLCHARACTERISTICS_NO_BIND      0x0800     // Do not bind this image.
#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER 0x1000     // Image should execute in an AppContainer
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER   0x2000     // Driver uses WDM model
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF     0x4000     // Image supports Control Flow Guard.
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE     0x8000

// Directory Entries

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor


typedef struct _IO_STATUS_BLOCK
{
    union
    {
        LONG Status;                                                        //0x0
        VOID* Pointer;                                                      //0x0
    };
    ULONGLONG Information;                                                  //0x8
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef enum _FILE_INFORMATION_CLASS
{
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation = 2,
    FileBothDirectoryInformation = 3,
    FileBasicInformation = 4,
    FileStandardInformation = 5,
    FileInternalInformation = 6,
    FileEaInformation = 7,
    FileAccessInformation = 8,
    FileNameInformation = 9,
    FileRenameInformation = 10,
    FileLinkInformation = 11,
    FileNamesInformation = 12,
    FileDispositionInformation = 13,
    FilePositionInformation = 14,
    FileFullEaInformation = 15,
    FileModeInformation = 16,
    FileAlignmentInformation = 17,
    FileAllInformation = 18,
    FileAllocationInformation = 19,
    FileEndOfFileInformation = 20,
    FileAlternateNameInformation = 21,
    FileStreamInformation = 22,
    FilePipeInformation = 23,
    FilePipeLocalInformation = 24,
    FilePipeRemoteInformation = 25,
    FileMailslotQueryInformation = 26,
    FileMailslotSetInformation = 27,
    FileCompressionInformation = 28,
    FileObjectIdInformation = 29,
    FileCompletionInformation = 30,
    FileMoveClusterInformation = 31,
    FileQuotaInformation = 32,
    FileReparsePointInformation = 33,
    FileNetworkOpenInformation = 34,
    FileAttributeTagInformation = 35,
    FileTrackingInformation = 36,
    FileIdBothDirectoryInformation = 37,
    FileIdFullDirectoryInformation = 38,
    FileValidDataLengthInformation = 39,
    FileShortNameInformation = 40,
    FileIoCompletionNotificationInformation = 41,
    FileIoStatusBlockRangeInformation = 42,
    FileIoPriorityHintInformation = 43,
    FileSfioReserveInformation = 44,
    FileSfioVolumeInformation = 45,
    FileHardLinkInformation = 46,
    FileProcessIdsUsingFileInformation = 47,
    FileNormalizedNameInformation = 48,
    FileNetworkPhysicalNameInformation = 49,
    FileIdGlobalTxDirectoryInformation = 50,
    FileIsRemoteDeviceInformation = 51,
    FileUnusedInformation = 52,
    FileNumaNodeInformation = 53,
    FileStandardLinkInformation = 54,
    FileRemoteProtocolInformation = 55,
    FileRenameInformationBypassAccessCheck = 56,
    FileLinkInformationBypassAccessCheck = 57,
    FileVolumeNameInformation = 58,
    FileIdInformation = 59,
    FileIdExtdDirectoryInformation = 60,
    FileReplaceCompletionInformation = 61,
    FileHardLinkFullIdInformation = 62,
    FileIdExtdBothDirectoryInformation = 63,
    FileDispositionInformationEx = 64,
    FileRenameInformationEx = 65,
    FileRenameInformationExBypassAccessCheck = 66,
    FileDesiredStorageClassInformation = 67,
    FileStatInformation = 68,
    FileMemoryPartitionInformation = 69,
    FileStatLxInformation = 70,
    FileCaseSensitiveInformation = 71,
    FileLinkInformationEx = 72,
    FileLinkInformationExBypassAccessCheck = 73,
    FileStorageReserveIdInformation = 74,
    FileCaseSensitiveInformationForceAccessCheck = 75,
    FileMaximumInformation = 76
} FILE_INFORMATION_CLASS;

typedef struct _FILE_STANDARD_INFORMATION
{
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_INFORMATION, * PFILE_STANDARD_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION_EX
{
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
    BOOLEAN AlternateStream;
    BOOLEAN MetadataAttribute;
} FILE_STANDARD_INFORMATION_EX, * PFILE_STANDARD_INFORMATION_EX;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemPathInformation = 4,
    SystemProcessInformation = 5,
    SystemCallCountInformation = 6,
    SystemDeviceInformation = 7,
    SystemProcessorPerformanceInformation = 8,
    SystemFlagsInformation = 9,
    SystemCallTimeInformation = 10,
    SystemModuleInformation = 11,
    SystemLocksInformation = 12,
    SystemStackTraceInformation = 13,
    SystemPagedPoolInformation = 14,
    SystemNonPagedPoolInformation = 15,
    SystemHandleInformation = 16,
    SystemObjectInformation = 17,
    SystemPageFileInformation = 18,
    SystemVdmInstemulInformation = 19,
    SystemVdmBopInformation = 20,
    SystemFileCacheInformation = 21,
    SystemPoolTagInformation = 22,
    SystemInterruptInformation = 23,
    SystemDpcBehaviorInformation = 24,
    SystemFullMemoryInformation = 25,
    SystemLoadGdiDriverInformation = 26,
    SystemUnloadGdiDriverInformation = 27,
    SystemTimeAdjustmentInformation = 28,
    SystemSummaryMemoryInformation = 29,
    SystemMirrorMemoryInformation = 30,
    SystemPerformanceTraceInformation = 31,
    SystemObsolete0 = 32,
    SystemExceptionInformation = 33,
    SystemCrashDumpStateInformation = 34,
    SystemKernelDebuggerInformation = 35,
    SystemContextSwitchInformation = 36,
    SystemRegistryQuotaInformation = 37,
    SystemExtendServiceTableInformation = 38,
    SystemPrioritySeperation = 39,
    SystemVerifierAddDriverInformation = 40,
    SystemVerifierRemoveDriverInformation = 41,
    SystemProcessorIdleInformation = 42,
    SystemLegacyDriverInformation = 43,
    SystemCurrentTimeZoneInformation = 44,
    SystemLookasideInformation = 45,
    SystemTimeSlipNotification = 46,
    SystemSessionCreate = 47,
    SystemSessionDetach = 48,
    SystemSessionInformation = 49,
    SystemRangeStartInformation = 50,
    SystemVerifierInformation = 51,
    SystemVerifierThunkExtend = 52,
    SystemSessionProcessInformation = 53,
    SystemLoadGdiDriverInSystemSpace = 54,
    SystemNumaProcessorMap = 55,
    SystemPrefetcherInformation = 56,
    SystemExtendedProcessInformation = 57,
    SystemRecommendedSharedDataAlignment = 58,
    SystemComPlusPackage = 59,
    SystemNumaAvailableMemory = 60,
    SystemProcessorPowerInformation = 61,
    SystemEmulationBasicInformation = 62,
    SystemEmulationProcessorInformation = 63,
    SystemExtendedHandleInformation = 64,
    SystemLostDelayedWriteInformation = 65,
    SystemBigPoolInformation = 66,
    SystemSessionPoolTagInformation = 67,
    SystemSessionMappedViewInformation = 68,
    SystemHotpatchInformation = 69,
    SystemObjectSecurityMode = 70,
    SystemWatchdogTimerHandler = 71,
    SystemWatchdogTimerInformation = 72,
    SystemLogicalProcessorInformation = 73,
    SystemWow64SharedInformationObsolete = 74,
    SystemRegisterFirmwareTableInformationHandler = 75,
    SystemFirmwareTableInformation = 76,
    SystemModuleInformationEx = 77,
    SystemVerifierTriageInformation = 78,
    SystemSuperfetchInformation = 79,
    SystemMemoryListInformation = 80,
    SystemFileCacheInformationEx = 81,
    SystemThreadPriorityClientIdInformation = 82,
    SystemProcessorIdleCycleTimeInformation = 83,
    SystemVerifierCancellationInformation = 84,
    SystemProcessorPowerInformationEx = 85,
    SystemRefTraceInformation = 86,
    SystemSpecialPoolInformation = 87,
    SystemProcessIdInformation = 88,
    SystemErrorPortInformation = 89,
    SystemBootEnvironmentInformation = 90,
    SystemHypervisorInformation = 91,
    SystemVerifierInformationEx = 92,
    SystemTimeZoneInformation = 93,
    SystemImageFileExecutionOptionsInformation = 94,
    SystemCoverageInformation = 95,
    SystemPrefetchPatchInformation = 96,
    SystemVerifierFaultsInformation = 97,
    SystemSystemPartitionInformation = 98,
    SystemSystemDiskInformation = 99,
    SystemProcessorPerformanceDistribution = 100,
    SystemNumaProximityNodeInformation = 101,
    SystemDynamicTimeZoneInformation = 102,
    SystemCodeIntegrityInformation = 103,
    SystemProcessorMicrocodeUpdateInformation = 104,
    SystemProcessorBrandString = 105,
    SystemVirtualAddressInformation = 106,
    SystemLogicalProcessorAndGroupInformation = 107,
    SystemProcessorCycleTimeInformation = 108,
    SystemStoreInformation = 109,
    SystemRegistryAppendString = 110,
    SystemAitSamplingValue = 111,
    SystemVhdBootInformation = 112,
    SystemCpuQuotaInformation = 113,
    SystemNativeBasicInformation = 114,
    SystemErrorPortTimeouts = 115,
    SystemLowPriorityIoInformation = 116,
    SystemBootEntropyInformation = 117,
    SystemVerifierCountersInformation = 118,
    SystemPagedPoolInformationEx = 119,
    SystemSystemPtesInformationEx = 120,
    SystemNodeDistanceInformation = 121,
    SystemAcpiAuditInformation = 122,
    SystemBasicPerformanceInformation = 123,
    SystemQueryPerformanceCounterInformation = 124,
    SystemSessionBigPoolInformation = 125,
    SystemBootGraphicsInformation = 126,
    SystemScrubPhysicalMemoryInformation = 127,
    SystemBadPageInformation = 128,
    SystemProcessorProfileControlArea = 129,
    SystemCombinePhysicalMemoryInformation = 130,
    SystemEntropyInterruptTimingInformation = 131,
    SystemConsoleInformation = 132,
    SystemPlatformBinaryInformation = 133,
    SystemPolicyInformation = 134,
    SystemHypervisorProcessorCountInformation = 135,
    SystemDeviceDataInformation = 136,
    SystemDeviceDataEnumerationInformation = 137,
    SystemMemoryTopologyInformation = 138,
    SystemMemoryChannelInformation = 139,
    SystemBootLogoInformation = 140,
    SystemProcessorPerformanceInformationEx = 141,
    SystemCriticalProcessErrorLogInformation = 142,
    SystemSecureBootPolicyInformation = 143,
    SystemPageFileInformationEx = 144,
    SystemSecureBootInformation = 145,
    SystemEntropyInterruptTimingRawInformation = 146,
    SystemPortableWorkspaceEfiLauncherInformation = 147,
    SystemFullProcessInformation = 148,
    SystemKernelDebuggerInformationEx = 149,
    SystemBootMetadataInformation = 150,
    SystemSoftRebootInformation = 151,
    SystemElamCertificateInformation = 152,
    SystemOfflineDumpConfigInformation = 153,
    SystemProcessorFeaturesInformation = 154,
    SystemRegistryReconciliationInformation = 155,
    SystemEdidInformation = 156,
    SystemManufacturingInformation = 157,
    SystemEnergyEstimationConfigInformation = 158,
    SystemHypervisorDetailInformation = 159,
    SystemProcessorCycleStatsInformation = 160,
    SystemVmGenerationCountInformation = 161,
    SystemTrustedPlatformModuleInformation = 162,
    SystemKernelDebuggerFlags = 163,
    SystemCodeIntegrityPolicyInformation = 164,
    SystemIsolatedUserModeInformation = 165,
    SystemHardwareSecurityTestInterfaceResultsInformation = 166,
    SystemSingleModuleInformation = 167,
    SystemAllowedCpuSetsInformation = 168,
    SystemVsmProtectionInformation = 169,
    SystemInterruptCpuSetsInformation = 170,
    SystemSecureBootPolicyFullInformation = 171,
    SystemCodeIntegrityPolicyFullInformation = 172,
    SystemAffinitizedInterruptProcessorInformation = 173,
    SystemRootSiloInformation = 174,
    SystemCpuSetInformation = 175,
    SystemCpuSetTagInformation = 176,
    SystemWin32WerStartCallout = 177,
    SystemSecureKernelProfileInformation = 178,
    SystemCodeIntegrityPlatformManifestInformation = 179,
    SystemInterruptSteeringInformation = 180,
    SystemSupportedProcessorArchitectures = 181,
    SystemMemoryUsageInformation = 182,
    SystemCodeIntegrityCertificateInformation = 183,
    SystemPhysicalMemoryInformation = 184,
    SystemControlFlowTransition = 185,
    SystemKernelDebuggingAllowed = 186,
    SystemActivityModerationExeState = 187,
    SystemActivityModerationUserSettings = 188,
    SystemCodeIntegrityPoliciesFullInformation = 189,
    SystemCodeIntegrityUnlockInformation = 190,
    SystemIntegrityQuotaInformation = 191,
    SystemFlushInformation = 192,
    SystemProcessorIdleMaskInformation = 193,
    SystemSecureDumpEncryptionInformation = 194,
    SystemWriteConstraintInformation = 195,
    SystemKernelVaShadowInformation = 196,
    SystemHypervisorSharedPageInformation = 197,
    SystemFirmwareBootPerformanceInformation = 198,
    SystemCodeIntegrityVerificationInformation = 199,
    SystemFirmwarePartitionInformation = 200,
    SystemSpeculationControlInformation = 201,
    SystemDmaGuardPolicyInformation = 202,
    SystemEnclaveLaunchControlInformation = 203,
    SystemWorkloadAllowedCpuSetsInformation = 204,
    SystemCodeIntegrityUnlockModeInformation = 205,
    SystemLeapSecondInformation = 206,
    SystemFlags2Information = 207,
    SystemSecurityModelInformation = 208,
    SystemCodeIntegritySyntheticCacheInformation = 209,
    SystemFeatureConfigurationInformation = 210,
    SystemFeatureConfigurationSectionInformation = 211,
    SystemFeatureUsageSubscriptionInformation = 212,
    SystemSecureSpeculationControlInformation = 213,
    SystemSpacesBootInformation = 214,
    SystemFwRamdiskInformation = 215,
    SystemWheaIpmiHardwareInformation = 216,
    SystemDifSetRuleClassInformation = 217,
    SystemDifClearRuleClassInformation = 218,
    SystemDifApplyPluginVerificationOnDriver = 219,
    SystemDifRemovePluginVerificationOnDriver = 220,
    SystemShadowStackInformation = 221,
    SystemBuildVersionInformation = 222,
    SystemPoolLimitInformation = 223,
    SystemCodeIntegrityAddDynamicStore = 224,
    SystemCodeIntegrityClearDynamicStores = 225,
    SystemPoolZeroingInformation = 227,
    MaxSystemInfoClass = 228
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;
typedef LONG KPRIORITY;
typedef enum _KWAIT_REASON {
    Executive,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrEventPair,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    WrKeyedEvent,
    WrTerminated,
    WrProcessInSwap,
    WrCpuRateControl,
    WrCalloutStack,
    WrKernel,
    WrResource,
    WrPushLock,
    WrMutex,
    WrQuantumEnd,
    WrDispatchInt,
    WrPreempted,
    WrYieldExecution,
    WrFastMutex,
    WrGuardedMutex,
    WrRundown,
    MaximumWaitReason
} KWAIT_REASON;
typedef struct _SYSTEM_THREAD {
    LARGE_INTEGER           KernelTime;
    LARGE_INTEGER           UserTime;
    LARGE_INTEGER           CreateTime;
    ULONG                   WaitTime;
    PVOID                   StartAddress;
    CLIENT_ID               ClientId;
    KPRIORITY               Priority;
    LONG                    BasePriority;
    ULONG                   ContextSwitchCount;
    ULONG                   State;
    KWAIT_REASON            WaitReason;
} SYSTEM_THREAD, * PSYSTEM_THREAD;
typedef struct _VM_COUNTERS {
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
} VM_COUNTERS, *PVM_COUNTERS;
typedef struct _IO_COUNTERS {
    ULONGLONG  ReadOperationCount;
    ULONGLONG  WriteOperationCount;
    ULONGLONG  OtherOperationCount;
    ULONGLONG ReadTransferCount;
    ULONGLONG WriteTransferCount;
    ULONGLONG OtherTransferCount;
} IO_COUNTERS, *PIO_COUNTERS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE ParentProcessId;
    ULONG HandleCount;
    LPCWSTR Reserved2[2];
    ULONG PrivatePageCount;
    VM_COUNTERS VirtualMemoryCounters;
    IO_COUNTERS IoCounters;
    SYSTEM_THREAD Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;
typedef struct _KSYSTEM_TIME
{
    ULONG LowPart;                                                          //0x0
    LONG High1Time;                                                         //0x4
    LONG High2Time;                                                         //0x8
} KSYSTEM_TIME, *PKSYSTEM_TIME;
typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE
{
    StandardDesign = 0,
    NEC98x86 = 1,
    EndAlternatives = 2
} ALTERNATIVE_ARCHITECTURE_TYPE;
typedef enum _NT_PRODUCT_TYPE
{
    NtProductWinNt = 1,
    NtProductLanManNt = 2,
    NtProductServer = 3
} NT_PRODUCT_TYPE;
typedef struct _XSTATE_FEATURE
{
    ULONG Offset;                                                           //0x0
    ULONG Size;                                                             //0x4
} XSTATE_FEATURE;
typedef struct _XSTATE_CONFIGURATION
{
    ULONGLONG EnabledFeatures;                                              //0x0
    ULONGLONG EnabledVolatileFeatures;                                      //0x8
    ULONG Size;                                                             //0x10
    union
    {
        ULONG ControlFlags;                                                 //0x14
        struct
        {
            ULONG OptimizedSave : 1;                                          //0x14
            ULONG CompactionEnabled : 1;                                      //0x14
            ULONG ExtendedFeatureDisable : 1;                                 //0x14
        };
    };
    XSTATE_FEATURE Features[64];                                            //0x18
    ULONGLONG EnabledSupervisorFeatures;                                    //0x218
    ULONGLONG AlignedFeatures;                                              //0x220
    ULONG AllFeatureSize;                                                   //0x228
    ULONG AllFeatures[64];                                                  //0x22c
    ULONGLONG EnabledUserVisibleSupervisorFeatures;                         //0x330
    ULONGLONG ExtendedFeatureDisableFeatures;                               //0x338
    ULONG AllNonLargeFeatureSize;                                           //0x340
    ULONG Spare;                                                            //0x344
} XSTATE_CONFIGURATION, *PXSTATE_CONFIGURATION;
typedef struct _KUSER_SHARED_DATA
{
    ULONG TickCountLowDeprecated;                                           //0x0
    ULONG TickCountMultiplier;                                              //0x4
    volatile KSYSTEM_TIME InterruptTime;                                    //0x8
    volatile KSYSTEM_TIME SystemTime;                                       //0x14
    volatile KSYSTEM_TIME TimeZoneBias;                                     //0x20
    USHORT ImageNumberLow;                                                  //0x2c
    USHORT ImageNumberHigh;                                                 //0x2e
    WCHAR NtSystemRoot[260];                                                //0x30
    ULONG MaxStackTraceDepth;                                               //0x238
    ULONG CryptoExponent;                                                   //0x23c
    ULONG TimeZoneId;                                                       //0x240
    ULONG LargePageMinimum;                                                 //0x244
    ULONG AitSamplingValue;                                                 //0x248
    ULONG AppCompatFlag;                                                    //0x24c
    ULONGLONG RNGSeedVersion;                                               //0x250
    ULONG GlobalValidationRunlevel;                                         //0x258
    volatile LONG TimeZoneBiasStamp;                                        //0x25c
    ULONG NtBuildNumber;                                                    //0x260
    NT_PRODUCT_TYPE NtProductType;                                          //0x264
    UCHAR ProductTypeIsValid;                                               //0x268
    UCHAR Reserved0[1];                                                     //0x269
    USHORT NativeProcessorArchitecture;                                     //0x26a
    ULONG NtMajorVersion;                                                   //0x26c
    ULONG NtMinorVersion;                                                   //0x270
    UCHAR ProcessorFeatures[64];                                            //0x274
    ULONG Reserved1;                                                        //0x2b4
    ULONG Reserved3;                                                        //0x2b8
    volatile ULONG TimeSlip;                                                //0x2bc
    ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;                  //0x2c0
    ULONG BootId;                                                           //0x2c4
    LARGE_INTEGER SystemExpirationDate;                                     //0x2c8
    ULONG SuiteMask;                                                        //0x2d0
    UCHAR KdDebuggerEnabled;                                                //0x2d4
    union
    {
        UCHAR MitigationPolicies;                                           //0x2d5
        struct
        {
            UCHAR NXSupportPolicy : 2;                                        //0x2d5
            UCHAR SEHValidationPolicy : 2;                                    //0x2d5
            UCHAR CurDirDevicesSkippedForDlls : 2;                            //0x2d5
            UCHAR Reserved : 2;                                               //0x2d5
        };
    };
    USHORT CyclesPerYield;                                                  //0x2d6
    volatile ULONG ActiveConsoleId;                                         //0x2d8
    volatile ULONG DismountCount;                                           //0x2dc
    ULONG ComPlusPackage;                                                   //0x2e0
    ULONG LastSystemRITEventTickCount;                                      //0x2e4
    ULONG NumberOfPhysicalPages;                                            //0x2e8
    UCHAR SafeBootMode;                                                     //0x2ec
    UCHAR VirtualizationFlags;                                              //0x2ed
    UCHAR Reserved12[2];                                                    //0x2ee
    union
    {
        ULONG SharedDataFlags;                                              //0x2f0
        struct
        {
            ULONG DbgErrorPortPresent : 1;                                    //0x2f0
            ULONG DbgElevationEnabled : 1;                                    //0x2f0
            ULONG DbgVirtEnabled : 1;                                         //0x2f0
            ULONG DbgInstallerDetectEnabled : 1;                              //0x2f0
            ULONG DbgLkgEnabled : 1;                                          //0x2f0
            ULONG DbgDynProcessorEnabled : 1;                                 //0x2f0
            ULONG DbgConsoleBrokerEnabled : 1;                                //0x2f0
            ULONG DbgSecureBootEnabled : 1;                                   //0x2f0
            ULONG DbgMultiSessionSku : 1;                                     //0x2f0
            ULONG DbgMultiUsersInSessionSku : 1;                              //0x2f0
            ULONG DbgStateSeparationEnabled : 1;                              //0x2f0
            ULONG SpareBits : 21;                                             //0x2f0
        };
    };
    ULONG DataFlagsPad[1];                                                  //0x2f4
    ULONGLONG TestRetInstruction;                                           //0x2f8
    LONGLONG QpcFrequency;                                                  //0x300
    ULONG SystemCall;                                                       //0x308
    ULONG Reserved2;                                                        //0x30c
    ULONGLONG SystemCallPad[2];                                             //0x310
    union
    {
        volatile KSYSTEM_TIME TickCount;                                    //0x320
        volatile ULONGLONG TickCountQuad;                                   //0x320
        ULONG ReservedTickCountOverlay[3];                                  //0x320
    };
    ULONG TickCountPad[1];                                                  //0x32c
    ULONG Cookie;                                                           //0x330
    ULONG CookiePad[1];                                                     //0x334
    LONGLONG ConsoleSessionForegroundProcessId;                             //0x338
    ULONGLONG TimeUpdateLock;                                               //0x340
    ULONGLONG BaselineSystemTimeQpc;                                        //0x348
    ULONGLONG BaselineInterruptTimeQpc;                                     //0x350
    ULONGLONG QpcSystemTimeIncrement;                                       //0x358
    ULONGLONG QpcInterruptTimeIncrement;                                    //0x360
    UCHAR QpcSystemTimeIncrementShift;                                      //0x368
    UCHAR QpcInterruptTimeIncrementShift;                                   //0x369
    USHORT UnparkedProcessorCount;                                          //0x36a
    ULONG EnclaveFeatureMask[4];                                            //0x36c
    ULONG TelemetryCoverageRound;                                           //0x37c
    USHORT UserModeGlobalLogger[16];                                        //0x380
    ULONG ImageFileExecutionOptions;                                        //0x3a0
    ULONG LangGenerationCount;                                              //0x3a4
    ULONGLONG Reserved4;                                                    //0x3a8
    volatile ULONGLONG InterruptTimeBias;                                   //0x3b0
    volatile ULONGLONG QpcBias;                                             //0x3b8
    ULONG ActiveProcessorCount;                                             //0x3c0
    volatile UCHAR ActiveGroupCount;                                        //0x3c4
    UCHAR Reserved9;                                                        //0x3c5
    union
    {
        USHORT QpcData;                                                     //0x3c6
        struct
        {
            volatile UCHAR QpcBypassEnabled;                                //0x3c6
            UCHAR QpcShift;                                                 //0x3c7
        };
    };
    LARGE_INTEGER TimeZoneBiasEffectiveStart;                               //0x3c8
    LARGE_INTEGER TimeZoneBiasEffectiveEnd;                                 //0x3d0
    XSTATE_CONFIGURATION XState;                                            //0x3d8
    KSYSTEM_TIME FeatureConfigurationChangeStamp;                           //0x720
    ULONG Spare;                                                            //0x72c
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;
#define TU(c) (((c > 96) && (c < 123)) ? (c - 32) : (c))
inline int stricmpA(const char* a, const char* b)
{
    int r = 0;
    while ((*a) && (*b) && (TU(*a++) == TU(*b++)))  ++r;
    r = (!((*a) || (*b)) ? (0) : ((TU(*a) > TU(*b)) ?
        (r + 1) : -(r + 1)));
    return r;
}
inline int stricmpW(const wchar_t* a, const wchar_t* b)
{
    int r = 0;
    while ((*a) && (*b) && (TU(*a++) == TU(*b++)))  ++r;
    r = (!((*a) || (*b)) ? (0) : ((TU(*a) > TU(*b)) ?
        (r + 1) : -(r + 1)));
    return r;
}
inline int strcmpA(const char* a, const char* b) {
    while (*a && *a == *b) { ++a; ++b; }
    return (int)(unsigned char)(*a) - (int)(unsigned char)(*b);
}
inline int strcmpW(const wchar_t* a, const wchar_t* b)
{
    while (*a == *b++) if (*a++ == L'\0') return 0;
    return (*(const unsigned int*)a - *(const unsigned int*)--b);
}
inline size_t strlenA(const char* str)
{
    size_t len = 0;
    size_t i = 0;
    while (str[i++]) ++len;
    return len;
}
inline size_t strlenW(const wchar_t* str)
{
    size_t len = 0;
    size_t i = 0;
    while (str[i++]) ++len;
    return len;
}
inline const char* strchrA(const char* str, const char ch)
{
    while (*str && *str != ch) str++;
    return *str == ch ? str : 0;
}
inline const wchar_t* strchrW(const wchar_t* str, const wchar_t ch)
{
    while (*str && *str != ch) str++;
    return *str == ch ? str : NULL;
}
inline int atoi(char* str)
{
    int res = 0;
    for (int i = 0; str[i] != '\0'; ++i)
        res = res * 10 + str[i] - '0';
    return res;
}
inline int wcsnicmp(const wchar_t* string1, const wchar_t* string2, size_t count)
{
    wchar_t f = 0, l = 0;
    if (!count) return 0;
    do {
        f = *string1 <= L'Z' && *string1 >= L'A'
            ? *string1 - L'A' + L'a'
            : *string1;
        l = *string2 <= L'Z' && *string2 >= L'A'
            ? *string2 - L'A' + L'a'
            : *string2;
        string1++;
        string2++;
    } while (--count && f && f == l);
    return f - l;
}
inline int wcsicmp(const wchar_t* string1, const wchar_t* string2)
{
    wchar_t f = 0, l = 0;
    do {
        f = *string1 <= L'Z' && *string1 >= L'A'
            ? *string1 + L'a' - L'A'
            : *string1;
        l = *string2 <= L'Z' && *string2 >= L'A'
            ? *string2 + L'a' - L'A'
            : *string2;
        string1++;
        string2++;
    } while (f && f == l);
    return f - l;
}
inline size_t mbstowcs(wchar_t* wcstr, const unsigned char* mbstr, size_t count)
{
    size_t size;
    size_t i;

    if (count <= 0 || !mbstr || !wcstr)
        return 0;

    if (!*mbstr)
        return 0;

    for (size = 0, i = 0; i < count; size++) {
        int result;

        if (mbstr[i] == 0) {
            result = 0;
        } else {
            wcstr[size] = mbstr[i];
            result = 1;
        }
        if (result == -1) {
            return -1;
        }
        if (result == 0) {
            wcstr[size] = L'\0';
            break;
        }
        i += result;
    }
    return size;
}
#pragma function(memcpy)
inline void* memcpy(char* dst, char* src, size_t len)
{
    if (CPUFeatures.cpu_FSRM)
        __movsb((unsigned char*)dst, (unsigned char*)src, len);
    else
        for (size_t i = 0; i < len; dst[i] = src[i], i++);
    return dst;
}
#pragma function(memset)
inline void* memset(void* dst, int val, size_t len)
{
    unsigned char* ptr_byte = dst;
    if (CPUFeatures.cpu_FSRM)
        __stosb(dst, (unsigned char)val, len);
    else
        for (size_t i = 0; i < len; ptr_byte[i] = (unsigned char)val, i++);
    return dst;
}

#pragma function(strcpy)
inline char* strcpy(char* dst, const char* src)
{
    char* ret = dst;
    while ((*dst++ = *src++));
    return ret;
}
inline WCHAR* wstrcpy(WCHAR* dst, const WCHAR* src)
{
    WCHAR* ret = dst;
    while ((*dst++ = *src++));
    return ret;
}
inline char* strcatA(char* dst, const char* src)
{
    char* d = dst;
    while (*d) d++;
    while ((*d++ = *src++));
    return dst;
}

inline WCHAR* strcatW(WCHAR* dst, const WCHAR* src)
{
    WCHAR* d = dst;
    while (*d) d++;
    while ((*d++ = *src++));
    return dst;
}

typedef struct _RUN_ENTRY {
    ULONG BaseCode;
    USHORT RunLength;
    USHORT CodeSize;
} RUN_ENTRY, * PRUN_ENTRY;

#pragma region Translation table
static const RUN_ENTRY RtlpRunTable[] = {
    {0x00000000, 0x0001, 0x0001},
    {0x00000103, 0x0001, 0x0001},
    {0x00000105, 0x0003, 0x0001},
    {0x0000010c, 0x0002, 0x0001},
    {0x00000121, 0x0001, 0x0001},
    {0x40000002, 0x0001, 0x0001},
    {0x40000006, 0x0001, 0x0001},
    {0x40000008, 0x0002, 0x0001},
    {0x4000000c, 0x0002, 0x0001},
    {0x40000370, 0x0001, 0x0001},
    {0x40020056, 0x0001, 0x0001},
    {0x400200af, 0x0001, 0x0001},
    {0x401a000c, 0x0001, 0x0001},
    {0x80000001, 0x0006, 0x0002},
    {0x8000000b, 0x0001, 0x0001},
    {0x8000000d, 0x000a, 0x0001},
    {0x8000001a, 0x0006, 0x0001},
    {0x80000021, 0x0002, 0x0001},
    {0x80000025, 0x0001, 0x0001},
    {0x80000027, 0x0001, 0x0001},
    {0x80000288, 0x0002, 0x0001},
    {0x80090300, 0x0012, 0x0001},
    {0x80090316, 0x0003, 0x0001},
    {0x80090320, 0x0003, 0x0001},
    {0x80090325, 0x0005, 0x0001},
    {0x80090330, 0x0002, 0x0001},
    {0x80090347, 0x0001, 0x0001},
    {0x80090349, 0x0001, 0x0001},
    {0x80092010, 0x0001, 0x0001},
    {0x80092012, 0x0002, 0x0001},
    {0x80096004, 0x0001, 0x0001},
    {0x80130001, 0x0005, 0x0001},
    {0x80190009, 0x0001, 0x0001},
    {0xc0000001, 0x000b, 0x0001},
    {0xc000000d, 0x001a, 0x0002},
    {0xc000002a, 0x0004, 0x0002},
    {0xc0000030, 0x0001, 0x0001},
    {0xc0000032, 0x0004, 0x0001},
    {0xc0000037, 0x0001, 0x0001},
    {0xc0000039, 0x0071, 0x0002},
    {0xc00000ab, 0x000c, 0x0001},
    {0xc00000ba, 0x0019, 0x0001},
    {0xc00000d4, 0x0004, 0x0001},
    {0xc00000d9, 0x0002, 0x0001},
    {0xc00000dc, 0x000e, 0x0001},
    {0xc00000ed, 0x0012, 0x0001},
    {0xc0000100, 0x000c, 0x0001},
    {0xc000010d, 0x0002, 0x0001},
    {0xc0000117, 0x0001, 0x0001},
    {0xc000011b, 0x000e, 0x0001},
    {0xc000012b, 0x0001, 0x0001},
    {0xc000012d, 0x0005, 0x0001},
    {0xc0000133, 0x0001, 0x0001},
    {0xc0000135, 0x0001, 0x0001},
    {0xc0000138, 0x0002, 0x0001},
    {0xc000013b, 0x0008, 0x0001},
    {0xc0000148, 0x0002, 0x0001},
    {0xc000014b, 0x0003, 0x0001},
    {0xc000014f, 0x000f, 0x0001},
    {0xc000015f, 0x0002, 0x0001},
    {0xc0000162, 0x0001, 0x0001},
    {0xc0000165, 0x0009, 0x0001},
    {0xc0000172, 0x0007, 0x0001},
    {0xc000017a, 0x000d, 0x0001},
    {0xc0000188, 0x0009, 0x0001},
    {0xc0000192, 0x000a, 0x0001},
    {0xc0000202, 0x0002, 0x0001},
    {0xc0000203, 0x0015, 0x0001},
    {0xc000021c, 0x0001, 0x0001},
    {0xc0000220, 0x0002, 0x0001},
    {0xc0000224, 0x0002, 0x0001},
    {0xc0000227, 0x0001, 0x0001},
    {0xc0000229, 0x0003, 0x0002},
    {0xc000022d, 0x0001, 0x0001},
    {0xc0000230, 0x0001, 0x0001},
    {0xc0000233, 0x000f, 0x0001},
    {0xc0000243, 0x0001, 0x0001},
    {0xc0000246, 0x0004, 0x0001},
    {0xc0000253, 0x0001, 0x0001},
    {0xc0000253, 0x0001, 0x0001},
    {0xc0000257, 0x0001, 0x0001},
    {0xc0000259, 0x0001, 0x0001},
    {0xc000025e, 0x0001, 0x0001},
    {0xc0000262, 0x0004, 0x0001},
    {0xc0000267, 0x0001, 0x0001},
    {0xc000026a, 0x0001, 0x0001},
    {0xc000026c, 0x0003, 0x0001},
    {0xc0000272, 0x0001, 0x0001},
    {0xc0000275, 0x0005, 0x0001},
    {0xc0000280, 0x0002, 0x0001},
    {0xc0000283, 0x0005, 0x0001},
    {0xc000028a, 0x0002, 0x0001},
    {0xc000028d, 0x0007, 0x0001},
    {0xc0000295, 0x000b, 0x0001},
    {0xc00002a1, 0x0012, 0x0001},
    {0xc00002b6, 0x0003, 0x0001},
    {0xc00002c1, 0x0001, 0x0001},
    {0xc00002c3, 0x0001, 0x0001},
    {0xc00002c5, 0x0003, 0x0001},
    {0xc00002c9, 0x0005, 0x0001},
    {0xc00002cf, 0x0002, 0x0001},
    {0xc00002d4, 0x000a, 0x0001},
    {0xc00002df, 0x0009, 0x0001},
    {0xc00002e9, 0x0002, 0x0001},
    {0xc00002ec, 0x0020, 0x0002},
    {0xc0000320, 0x0003, 0x0002},
    {0xc0000350, 0x0003, 0x0002},
    {0xc0000354, 0x0001, 0x0001},
    {0xc0000356, 0x0007, 0x0002},
    {0xc0000361, 0x0004, 0x0001},
    {0xc000036b, 0x0002, 0x0001},
    {0xc000036f, 0x0001, 0x0001},
    {0xc0000380, 0x000e, 0x0002},
    {0xc000038f, 0x0001, 0x0002},
    {0xc0000401, 0x0006, 0x0001},
    {0xc0000408, 0x0009, 0x0002},
    {0xc0000412, 0x0003, 0x0001},
    {0xc0020001, 0x001d, 0x0001},
    {0xc002001f, 0x0001, 0x0001},
    {0xc0020021, 0x0006, 0x0001},
    {0xc0020028, 0x0026, 0x0001},
    {0xc002004f, 0x0007, 0x0001},
    {0xc0020057, 0x0002, 0x0001},
    {0xc0020062, 0x0002, 0x0001},
    {0xc0030001, 0x000c, 0x0001},
    {0xc0030059, 0x0009, 0x0001},
    {0xc00a0001, 0x0003, 0x0001},
    {0xc00a0006, 0x000b, 0x0001},
    {0xc00a0012, 0x0007, 0x0001},
    {0xc00a0022, 0x0001, 0x0001},
    {0xc00a0024, 0x0001, 0x0001},
    {0xc00a0026, 0x0003, 0x0001},
    {0xc00a002a, 0x0002, 0x0001},
    {0xc00a002e, 0x0004, 0x0001},
    {0xc00a0033, 0x0004, 0x0001},
    {0xc0130001, 0x0010, 0x0001},
    {0xc0130012, 0x0005, 0x0001},
    {0xc0150001, 0x0008, 0x0001},
    {0xc015000a, 0x0002, 0x0001},
    {0xc015000e, 0x0001, 0x0001},
    {0xc01a0001, 0x000b, 0x0001},
    {0xc01a000d, 0x0022, 0x0001},
    {0xc0980001, 0x0002, 0x0001},
    {0xc0980008, 0x0001, 0x0001},
    {0xffffffff, 0x0001, 0x0001},
    {0x0, 0x0, 0x0} };
static const USHORT RtlpStatusTable[] = {
    0x0000, 0x03e5, 0x00ea, 0x0514, 0x0515, 0x03fe, 0x0516,
    0x2009, 0x0057, 0x0517, 0x0460, 0x03f6, 0x0461, 0x0518,
    0x20ac, 0x0720, 0x0779, 0x19d3, 0x0001, 0x8000, 0x03e6, 0x0000,
    0x0003, 0x8000, 0x0004, 0x8000, 0x00ea, 0x0000, 0x0012, 0x0000,
    0x056f, 0x012b, 0x001c, 0x0015, 0x0015, 0x00aa, 0x0103,
    0x00fe, 0x00ff, 0x00ff, 0x0456, 0x0103, 0x044d, 0x0456,
    0x0457, 0x044c, 0x044e, 0x044f, 0x0450, 0x0962, 0x10f4,
    0x048d, 0x048e, 0x05aa, 0x0006, 0x0001, 0x0035, 0x054f,
    0x0554, 0x0120, 0x0554, 0x0057, 0x0057, 0x0032, 0x0558,
    0x052e, 0x0057, 0x0520, 0x0005, 0x0005, 0x051f, 0x0554,
    0x078b, 0x06f8, 0x0057, 0x007a, 0x0574, 0x06fe, 0x0057,
    0x0057, 0x0532, 0x1770, 0x1771, 0x0001, 0x0558, 0x0545,
    0x0575, 0x0575, 0x0575, 0x0575, 0x13c5, 0x13c6, 0x13c7,
    0x13c8, 0x13c9, 0x19e5, 0x001f, 0x0001, 0x0057, 0x0018,
    0x03e6, 0x03e7, 0x05ae, 0x0006, 0x03e9, 0x00c1, 0x0057,
    0x0057, 0x0000, 0x0002, 0x0000, 0x0002, 0x0000, 0x0001, 0x0000,
    0x0026, 0x0000, 0x0022, 0x0000, 0x0015, 0x0000, 0x06f9, 0x0000,
    0x001b, 0x0000, 0x00ea, 0x0000, 0x0008, 0x0000, 0x01e7, 0x0000,
    0x01e7, 0x0000, 0x0057, 0x0000, 0x0057, 0x0000, 0x0001, 0x0000,
    0x001d, 0xc000, 0x0005, 0x0000, 0x0005, 0x0000, 0x00c1, 0x0000,
    0x0005, 0x0000, 0x0005, 0x0000, 0x007a, 0x0000, 0x0006, 0x0000,
    0x0025, 0xc000, 0x0026, 0xc000, 0x009e, 0x0000, 0x002b, 0xc000,
    0x01e7, 0x0000, 0x01e7, 0x0000, 0x0057, 0x0571, 0x007b,
    0x0002, 0x00b7, 0x0006, 0x00a1, 0x0000, 0x0003, 0x0000,
    0x00a1, 0x0000, 0x045d, 0x0000, 0x045d, 0x0000, 0x0017, 0x0000,
    0x0017, 0x0000, 0x0008, 0x0000, 0x0005, 0x0000, 0x0006, 0x0000,
    0x0020, 0x0000, 0x0718, 0x0000, 0x0057, 0x0000, 0x0120, 0x0000,
    0x012a, 0x0000, 0x0057, 0x0000, 0x0057, 0x0000, 0x009c, 0x0000,
    0x0005, 0x0000, 0x0057, 0x0000, 0x0057, 0x0000, 0x0057, 0x0000,
    0x011a, 0x0000, 0x00ff, 0x0000, 0x0570, 0x0000, 0x0570, 0x0000,
    0x0570, 0x0000, 0x0021, 0x0000, 0x0021, 0x0000, 0x0005, 0x0000,
    0x0032, 0x0000, 0x0519, 0x0000, 0x051a, 0x0000, 0x051b, 0x0000,
    0x051c, 0x0000, 0x051d, 0x0000, 0x051e, 0x0000, 0x051f, 0x0000,
    0x0520, 0x0000, 0x0521, 0x0000, 0x0522, 0x0000, 0x0523, 0x0000,
    0x0524, 0x0000, 0x0525, 0x0000, 0x0526, 0x0000, 0x0527, 0x0000,
    0x0528, 0x0000, 0x0529, 0x0000, 0x052a, 0x0000, 0x0056, 0x0000,
    0x052c, 0x0000, 0x052d, 0x0000, 0x052e, 0x0000, 0x052f, 0x0000,
    0x0530, 0x0000, 0x0531, 0x0000, 0x0532, 0x0000, 0x0533, 0x0000,
    0x0534, 0x0000, 0x0535, 0x0000, 0x0536, 0x0000, 0x0537, 0x0000,
    0x0538, 0x0000, 0x0539, 0x0000, 0x053a, 0x0000, 0x007f, 0x0000,
    0x00c1, 0x0000, 0x03f0, 0x0000, 0x053c, 0x0000, 0x009e, 0x0000,
    0x0070, 0x0000, 0x053d, 0x0000, 0x053e, 0x0000, 0x0044, 0x0000,
    0x0103, 0x0000, 0x053f, 0x0000, 0x0103, 0x0000, 0x009a, 0x0000,
    0x000e, 0x0000, 0x01e7, 0x0000, 0x0714, 0x0000, 0x0715, 0x0000,
    0x0716, 0x0000, 0x008c, 0xc000, 0x008d, 0xc000, 0x008e, 0xc000,
    0x008f, 0xc000, 0x0090, 0xc000, 0x0091, 0xc000, 0x0092, 0xc000,
    0x0093, 0xc000, 0x0094, 0xc000, 0x0216, 0x0000, 0x0096, 0xc000,
    0x0008, 0x0000, 0x03ee, 0x0000, 0x0540, 0x0000, 0x05aa, 0x0000,
    0x0003, 0x0000, 0x0017, 0x0000, 0x048f, 0x0000, 0x0015, 0x0000,
    0x01e7, 0x0000, 0x01e7, 0x0000, 0x05ad, 0x0000, 0x0013, 0x0000,
    0x0015, 0x0000, 0x0541, 0x0000, 0x0542, 0x0000, 0x0543, 0x0000,
    0x0544, 0x0000, 0x0545, 0x0000, 0x0057, 0x0000, 0x00e7,
    0x00e7, 0x00e6, 0x00e7, 0x0001, 0x00e9, 0x00e8, 0x0217,
    0x0218, 0x00e6, 0x0079, 0x0026, 0x0005, 0x0032, 0x0033,
    0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039, 0x003a,
    0x003b, 0x003c, 0x003d, 0x003e, 0x003f, 0x0040, 0x0041,
    0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047, 0x0048,
    0x0058, 0x0011, 0x0005, 0x00f0, 0x0546, 0x00e8, 0x0547,
    0x0548, 0x0549, 0x054a, 0x054b, 0x054c, 0x054d, 0x012c,
    0x012d, 0x054e, 0x054f, 0x0550, 0x0551, 0x06f8, 0x045d,
    0x0552, 0x0553, 0x0057, 0x0057, 0x0057, 0x0057, 0x0057,
    0x0057, 0x0057, 0x0057, 0x0057, 0x0057, 0x0057, 0x0057,
    0x0003, 0x0420, 0x03e9, 0x0554, 0x00cb, 0x0091, 0x0570,
    0x010b, 0x0555, 0x0556, 0x00ce, 0x0961, 0x0964, 0x013d,
    0x0005, 0x0557, 0x0558, 0x0420, 0x05a4, 0x00c1, 0x0559,
    0x055a, 0x03ee, 0x0004, 0x03e3, 0x0005, 0x04ba, 0x0005,
    0x055b, 0x055c, 0x055d, 0x055e, 0x0006, 0x055f, 0x05af,
    0x00c1, 0x00c1, 0x00c1, 0x00c1, 0x0576, 0x007e, 0x00b6,
    0x007f, 0x0040, 0x0040, 0x0033, 0x003b, 0x003b, 0x003b,
    0x003b, 0x045a, 0x007c, 0x0056, 0x006d, 0x03f1, 0x03f8,
    0x03ed, 0x045e, 0x0560, 0x0561, 0x0562, 0x0563, 0x0564,
    0x0565, 0x0566, 0x0567, 0x03ef, 0x0568, 0x0569, 0x03f9,
    0x056a, 0x045d, 0x04db, 0x0459, 0x0462, 0x0463, 0x0464,
    0x0465, 0x0466, 0x0467, 0x0468, 0x045f, 0x045d, 0x0451,
    0x0452, 0x0453, 0x0454, 0x0455, 0x0469, 0x0458, 0x056b,
    0x056c, 0x03fa, 0x03fb, 0x056d, 0x056e, 0x03fc, 0x03fd,
    0x0057, 0x045d, 0x0016, 0x045d, 0x045d, 0x05de, 0x0013,
    0x06fa, 0x06fb, 0x06fc, 0x06fd, 0x05dc, 0x05dd, 0x06fe,
    0x0700, 0x0701, 0x046b, 0x04c3, 0x04c4, 0x05df, 0x070f,
    0x0710, 0x0711, 0x0712, 0x0572, 0x003b, 0x003b, 0x0717,
    0x046a, 0x06f8, 0x04be, 0x04be, 0x0044, 0x0034, 0x0040,
    0x0040, 0x0040, 0x0044, 0x003b, 0x003b, 0x003b, 0x003b,
    0x003b, 0x003b, 0x003b, 0x0032, 0x0032, 0x17e6, 0x046c,
    0x00c1, 0x0773, 0x0490, 0x04ff, 0x0057, 0x0000, 0x022a, 0xc000,
    0x022b, 0xc000, 0x04d5, 0x0492, 0x0774, 0x0775, 0x0006,
    0x04c9, 0x04ca, 0x04cb, 0x04cc, 0x04cd, 0x04ce, 0x04cf,
    0x04d0, 0x04d1, 0x04d2, 0x04d3, 0x04d4, 0x04c8, 0x04d6,
    0x04d7, 0x04d8, 0x00c1, 0x04d4, 0x054f, 0x04d0, 0x0573,
    0x0422, 0x00b6, 0x007f, 0x0120, 0x0476, 0x10fe, 0x1b8e,
    0x07d1, 0x04b1, 0x0015, 0x0491, 0x1126, 0x1129, 0x112a,
    0x1128, 0x0780, 0x0781, 0x00a1, 0x0488, 0x0489, 0x048a,
    0x048b, 0x048c, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005,
    0x0005, 0x1777, 0x1778, 0x1772, 0x1068, 0x1069, 0x106a,
    0x106b, 0x201a, 0x201b, 0x201c, 0x0001, 0x10ff, 0x1100,
    0x0494, 0x200a, 0x200b, 0x200c, 0x200d, 0x200e, 0x200f,
    0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2016,
    0x2017, 0x2018, 0x2019, 0x211e, 0x1127, 0x0651, 0x049a,
    0x049b, 0x2024, 0x0575, 0x03e6, 0x1075, 0x1076, 0x04ed,
    0x10e8, 0x2138, 0x04e3, 0x2139, 0x049d, 0x213a, 0x2141,
    0x2142, 0x2143, 0x2144, 0x2145, 0x2146, 0x2147, 0x2148,
    0x2149, 0x0032, 0x2151, 0x2152, 0x2153, 0x2154, 0x215d,
    0x2163, 0x2164, 0x2165, 0x216d, 0x0577, 0x0052, 0x2171, 0x0000,
    0x2172, 0x0000, 0x0333, 0x8009, 0x0334, 0x8009, 0x0002, 0x0000,
    0x0335, 0x8009, 0x0336, 0x8009, 0x0337, 0x8009, 0x0338, 0x8009,
    0x0339, 0x8009, 0x033a, 0x8009, 0x033b, 0x8009, 0x033c, 0x8009,
    0x033d, 0x8009, 0x033e, 0x8009, 0x0340, 0x8009, 0x0341, 0x8009,
    0x0342, 0x8009, 0x045b, 0x0000, 0x04e7, 0x0000, 0x04e6, 0x0000,
    0x106f, 0x0000, 0x1074, 0x0000, 0x106e, 0x0000, 0x012e, 0x0000,
    0x0305, 0x8003, 0x0306, 0x8003, 0x0307, 0x8003, 0x0308, 0x8003,
    0x0309, 0x8003, 0x030a, 0x8003, 0x030b, 0x8003, 0x04ef, 0x0000,
    0x04f0, 0x0000, 0x0348, 0x8009, 0x04e8, 0x0000, 0x0343, 0x8009,
    0x177d, 0x0000, 0x0504, 0x0001, 0xc009, 0x217c, 0x0000,
    0x2182, 0x0000, 0x00c1, 0x0000, 0x00c1, 0x0000, 0x0346, 0x8009,
    0x0572, 0x0000, 0x04ec, 0x04ec, 0x04ec, 0x04ec, 0x04fb,
    0x04fb, 0x04fc, 0x006b, 0x8010, 0x006c, 0x8010, 0x006f, 0x8010,
    0x000c, 0x8010, 0x000d, 0x8009, 0x002c, 0x8010, 0x0016, 0x8009,
    0x002f, 0x8010, 0x04f1, 0x0000, 0x0351, 0x8009, 0x0352, 0x8009,
    0x0353, 0x8009, 0x0354, 0x8009, 0x0355, 0x8009, 0x0022, 0x8009,
    0x078c, 0x078d, 0x078e, 0x217b, 0x219d, 0x219f, 0x052e, 0x0000,
    0x0502, 0x0000, 0x0356, 0x8009, 0x0357, 0x8009, 0x0358, 0x8009,
    0x0359, 0x8009, 0x035a, 0x8009, 0x035b, 0x8009, 0x0503, 0x0000,
    0x0505, 0x078f, 0x0506, 0x06a4, 0x06a5, 0x0006, 0x06a7,
    0x06a8, 0x06a9, 0x06aa, 0x06ab, 0x06ac, 0x06ad, 0x06ae,
    0x06af, 0x06b0, 0x06b1, 0x06b2, 0x06b3, 0x06b4, 0x06b5,
    0x06b6, 0x06b7, 0x06b8, 0x06b9, 0x06ba, 0x06bb, 0x06bc,
    0x06bd, 0x06be, 0x06bf, 0x06c0, 0x06c2, 0x06c4, 0x06c5,
    0x06c6, 0x06c7, 0x06c8, 0x06c9, 0x06cb, 0x06cc, 0x06cd,
    0x06ce, 0x06cf, 0x06d0, 0x06d1, 0x06d2, 0x06d3, 0x06d4,
    0x06d5, 0x06d6, 0x06d7, 0x06d8, 0x06d9, 0x06da, 0x06db,
    0x06dc, 0x06dd, 0x06de, 0x06df, 0x06e0, 0x06e1, 0x06e2,
    0x06e3, 0x06e4, 0x06e5, 0x06e6, 0x06e7, 0x06e8, 0x06e9,
    0x06ea, 0x06eb, 0x06ff, 0x070e, 0x076a, 0x076b, 0x076c,
    0x0719, 0x071a, 0x071b, 0x071c, 0x071d, 0x071e, 0x071f,
    0x0721, 0x0722, 0x077a, 0x077b, 0x06ec, 0x06ed, 0x06ee,
    0x0006, 0x0006, 0x06f1, 0x06f2, 0x06f3, 0x06f4, 0x06f5,
    0x06f6, 0x06f7, 0x0723, 0x0724, 0x0725, 0x0726, 0x0727,
    0x0728, 0x077c, 0x077d, 0x077e, 0x1b59, 0x1b5a, 0x1b5b,
    0x1b5f, 0x1b60, 0x1b61, 0x1b62, 0x1b63, 0x1b64, 0x1b65,
    0x1b66, 0x1b67, 0x1b68, 0x1b69, 0x1b8f, 0x1b8e, 0x1b90,
    0x1b6e, 0x1b6f, 0x1b70, 0x1b71, 0x1b7b, 0x1b7e, 0x1b80,
    0x1b81, 0x1b82, 0x1b84, 0x1b85, 0x1b89, 0x1b5c, 0x1b8a,
    0x1b8b, 0x1b8d, 0x1b8c, 0x1b92, 0x1b91, 0x13af, 0x13b0,
    0x13b1, 0x13b2, 0x13b3, 0x13b4, 0x13b5, 0x13b6, 0x13b7,
    0x13b8, 0x13b9, 0x13ba, 0x13bb, 0x13bc, 0x13bd, 0x13be,
    0x13c0, 0x13ce, 0x13c2, 0x13c3, 0x13c4, 0x36b0, 0x36b1,
    0x36b2, 0x36b3, 0x36b4, 0x36b5, 0x36b6, 0x36b7, 0x36b9,
    0x36ba, 0x36bb, 0x19c8, 0x19c9, 0x19ca, 0x19cb, 0x19cc,
    0x19cd, 0x19ce, 0x19cf, 0x19d0, 0x19d1, 0x19d2, 0x19d4,
    0x19d5, 0x19d6, 0x19d7, 0x19d8, 0x19d9, 0x19da, 0x19db,
    0x19dc, 0x19dd, 0x19de, 0x19df, 0x19e0, 0x19e1, 0x19e2,
    0x19e3, 0x19e4, 0x19e6, 0x19e7, 0x19e8, 0x19e9, 0x19ea,
    0x19eb, 0x19ec, 0x19ed, 0x19ee, 0x19ef, 0x19f0, 0x19f1,
    0x19f2, 0x19f3, 0x19f4, 0x19f5, 0x19f6, 0x0037, 0x0037,
    0x0037, 0x0000, 0x0 };
#pragma endregion
#define NtCurrentProcess()   ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread()    ((HANDLE)(LONG_PTR)-2)
#define NtGetPid()           NtGetTeb()->ClientId.UniqueProcess /* GetCurrentProcessId() */
#define NtGetTid()           NtGetTeb()->ClientId.UniqueThread  /* GetCurrentThreadId() */
#define GetLastError()       NtGetTeb()->LastErrorValue         /* GetLastError()*/
#define SetLastError(err)    NtGetTeb()->LastErrorValue = err   /* SetLastError()*/
#define GetLastNTError(err)  NtGetTeb()->LastStatusValue
inline ULONG RtlNtStatusToDosError(NTSTATUS status)
{
    if (status & 0x20000000) {
        return status;
    }
    if ((status & 0xffff0000) == 0x80070000) {
        return status & 0x0000ffff;
    }
    if ((status & 0xf0000000) == 0xd0000000) {
        status &= 0xcfffffff;
    }


    ULONG Entry = 0;
    ULONG Index = 0;
    do {
        if (status >= RtlpRunTable[Entry + 1].BaseCode) {
            Index += RtlpRunTable[Entry].RunLength * RtlpRunTable[Entry].CodeSize;

        }
        else {
            ULONG Offset = status - RtlpRunTable[Entry].BaseCode;
            if (Offset >= RtlpRunTable[Entry].RunLength) {
                break;

            }
            Index += (Offset * (ULONG)RtlpRunTable[Entry].CodeSize);
            if (RtlpRunTable[Entry].CodeSize == 1) {
                return RtlpStatusTable[Index];

            }
            return (ULONG)RtlpStatusTable[Index + 1] << 16 |
                (ULONG)RtlpStatusTable[Index];
        }

        Entry += 1;
    } while (Entry < (sizeof(RtlpRunTable) / sizeof(RUN_ENTRY)));


    if (status >> 16 == 0xC001) {
        return status & 0xFFFF;
    }


    return ERROR_MR_MID_NOT_FOUND;
}
#define INVALID_HANDLE_VALUE             ((HANDLE)(LONG_PTR)-1)
#define ERROR_INVALID_PARAMETER          87L
#define SetLastNTStatus(err) do {PTEB teb = NtGetTeb(); teb->LastStatusValue = err; } while(0)
#define SetLastNTError(err)  do {PTEB teb = NtGetTeb(); teb->LastStatusValue = err; teb->LastErrorValue = RtlNtStatusToDosError(err); } while(0)
inline PTEB NtGetTeb()
{
    static PTEB Teb = NULL;

    if (Teb) return Teb;
#if defined(_M_X64)
    Teb = (PTEB)(__readgsqword(0x30));
#elif defined(_M_IX86)
    Teb = (PTEB)(__readfsdword(0x18));
#elif defined(_M_ARM)
    Teb = *(PTEB)(_MoveFromCoprocessor(15, 0, 13, 0, 2));
#elif defined(_M_ARM64)
    Teb = *(PTEB*)(__getReg(18)); // TEB in x18
#elif defined(_M_IA64) || defined(_M_ALPHA) || defined(_M_PPC)
    Teb = *(PTEB*)((size_t)_rdteb()); // TEB in r13
#elif defined(_M_MIPS)
    Teb = *(PTEB*)(__gregister_get(13)); // TEB in r13
#endif
    return Teb;
}
inline PPEB NtGetPeb()
{
    static PPEB Peb = NULL;
    if(!Peb) Peb = NtGetTeb()->ProcessEnvironmentBlock;
    return Peb;
}

extern void cpu_detect_features(void);
extern NTSTATUS(__stdcall* NtClose)(HANDLE Handle);
extern NTSTATUS RtlInitUnicodeStringEx(PUNICODE_STRING DestinationString, PCWSTR SourceString);
