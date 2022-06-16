#pragma once
#include <intrin.h>

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
#define MAX_PATH          260

#define MAKEWORD(a, b)      ((WORD)(((BYTE)(((DWORD_PTR)(a)) & 0xff)) | ((WORD)((BYTE)(((DWORD_PTR)(b)) & 0xff))) << 8))
#define MAKELONG(a, b)      ((LONG)(((WORD)(((DWORD_PTR)(a)) & 0xffff)) | ((DWORD)((WORD)(((DWORD_PTR)(b)) & 0xffff))) << 16))
#define LOWORD(l)           ((WORD)(((DWORD_PTR)(l)) & 0xffff))
#define HIWORD(l)           ((WORD)((((DWORD_PTR)(l)) >> 16) & 0xffff))
#define LOBYTE(w)           ((BYTE)(((DWORD_PTR)(w)) & 0xff))
#define HIBYTE(w)           ((BYTE)((((DWORD_PTR)(w)) >> 8) & 0xff))
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
#define STATUS_WAIT_0                     ((DWORD)0x00000000L) 
#define STATUS_ABANDONED_WAIT_0           ((DWORD)0x00000080L)    
#define STATUS_USER_APC                   ((DWORD)0x000000C0L)    
#define STATUS_TIMEOUT                    ((DWORD)0x00000102L)    
#define STATUS_PENDING                    ((DWORD)0x00000103L)    
#define DBG_EXCEPTION_HANDLED             ((DWORD)0x00010001L)    
#define DBG_CONTINUE                      ((DWORD)0x00010002L)    
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
#define STATUS_NO_MEMORY                  ((DWORD)0xC0000017L)    
#define STATUS_ILLEGAL_INSTRUCTION        ((DWORD)0xC000001DL)    
#define STATUS_NONCONTINUABLE_EXCEPTION   ((DWORD)0xC0000025L)    
#define STATUS_INVALID_DISPOSITION        ((DWORD)0xC0000026L)    
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
#define STATUS_STACK_OVERFLOW             ((DWORD)0xC00000FDL)    
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

#define NULL 0
#define bool  _Bool
#define false 0
#define true  1

#define TH32CS_INHERIT 0x80000000
#define TH32CS_SNAPHEAPLIST 0x00000001
#define TH32CS_SNAPMODULE 0x00000008
#define TH32CS_SNAPMODULE32 0x00000010
#define TH32CS_SNAPPROCESS 0x00000002
#define TH32CS_SNAPTHREAD 0x00000004
#define TH32CS_SNAPALL TH32CS_SNAPHEAPLIST | TH32CS_SNAPMODULE | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD


typedef struct _LIST_ENTRY {
	struct _LIST_ENTRY* Flink;
	struct _LIST_ENTRY* Blink;
} LIST_ENTRY, * PLIST_ENTRY;

typedef struct _UNICODE_STRING {
	unsigned short	Length;
	unsigned short	MaximumLength;
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
	LIST_ENTRY			InLoadOrderLinks;				/* 0x00 */
	LIST_ENTRY			InMemoryOrderLinks;				/* 0x10 */
	LIST_ENTRY			InInitializationOrderLinks;		/* 0x20 */
	void* DllBase;						/* 0x30 */
	void* EntryPoint;						/* 0x38 */
	unsigned long		SizeOfImage;					/* 0x40 */
	UNICODE_STRING		FullDllName;					/* 0x48 */
	UNICODE_STRING		BaseDllName;					/* 0x58 */
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

typedef struct _PEB {
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages : 1;                                    //0x3
            UCHAR IsProtectedProcess : 1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
            UCHAR IsPackagedProcess : 1;                                      //0x3
            UCHAR IsAppContainer : 1;                                         //0x3
            UCHAR IsProtectedProcessLight : 1;                                //0x3
            UCHAR IsLongPathAwareProcess : 1;                                 //0x3
        };
    };
    VOID* Mutant;                                                           //0x4
    VOID* ImageBaseAddress;                                                 //0x8
    struct _PEB_LDR_DATA* Ldr;                                              //0xc
} PEB, * PPEB;

typedef struct _TIB {
	unsigned char	Stuff[0x60];
	PPEB			pPEB;
} TIB, * PTIB;


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

#ifndef _MAC
#include "poppack.h"                    // Back to 4 byte packing
#endif

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
#define IMAGE_FILE_LINE_NUMS_STRIPPED        0x0004  // Line nunbers stripped from file.
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


inline int strcmpA(const char* a, const char* b) {
    while (*a && *a == *b) { ++a; ++b; }
    return (int)(unsigned char)(*a) - (int)(unsigned char)(*b);
}
inline int strcmpW(const wchar_t* a, const wchar_t* b)
{
    while (*a == *b++) if (*a++ == '\0') return (0);
    return (*(const unsigned int*)a - *(const unsigned int*)--b);
}
inline int atoi(char* str)
{
    int res = 0;

    for (int i = 0; str[i] != '\0'; ++i)
        res = res * 10 + str[i] - '0';

    return res;
}
