#include "framework.h"
struct _CPUFeatures CPUFeatures;
#define CPU_FEATURE_SGX        1 << 2
#define CPU_FEATURE_FSRM       1 << 4
#define CPU_FEATURE_AVX2       1 << 5
#define CPU_FEATURE_FZRM       1 << 10
#define CPU_FEATURE_FSRS       1 << 11
#define CPU_FEATURE_FSRC       1 << 12
#define CPU_FEATURE_AES        1 << 25
#define CPU_FEATURE_SSE        1 << 25
#define CPU_FEATURE_SSE2       1 << 26
#define CPU_FEATURE_AVX        1 << 28
#define CPU_FEATURE_SHA        1 << 29
#define CPU_FEATURE_RDRAND     1 << 30
#define CPU_FEATURE_Hypervisor 1 << 31

#if !defined(_WIN32) && !(defined(_M_IX86) || defined(_M_X64))
void cpu_detect_features(void) {}
#else
typedef unsigned int uint32_t;
void cpuid(uint32_t funcId, uint32_t* eax, uint32_t* ebx, uint32_t* ecx, uint32_t* edx)
{

    int regs[4];
    __cpuid(regs, funcId);
    *eax = regs[0];
    *ebx = regs[1];
    *ecx = regs[2];
    *edx = regs[3];
}
void cpuidex(uint32_t funcId, uint32_t subFuncId, uint32_t* eax, uint32_t* ebx, uint32_t* ecx, uint32_t* edx)
{

    int regs[4];
    __cpuidex(regs, funcId, subFuncId);
    *eax = regs[0];
    *ebx = regs[1];
    *ecx = regs[2];
    *edx = regs[3];
}
#define SetFeature(variable, register) CPUFeatures.cpu_##variable = (register & CPU_FEATURE_##variable) != 0
void cpu_detect_features(void)
{
    uint32_t eax = 0;
    uint32_t ebx = 0;
    uint32_t ecx = 0;
    uint32_t edx = 0;

    cpuid(0, &eax, &ebx, &ecx, &edx);
    const uint32_t maxFunc = eax;
    //cpuid(0x80000000, &eax, &ebx, &ecx, &edx);
    //uint32_t maxFuncExtend = eax;
    if (maxFunc >= 1)
    {
        cpuid(1, &eax, &ebx, &ecx, &edx);
        SetFeature(SSE, edx);
        SetFeature(SSE2, edx);
        SetFeature(AVX, ecx);
        SetFeature(AES, ecx);
        SetFeature(RDRAND, ecx);
        SetFeature(Hypervisor, ecx);
    }
    if (maxFunc >= 7) {
        cpuid(7, &eax, &ebx, &ecx, &edx);
        SetFeature(FSRM, edx);
        SetFeature(SGX, ebx);
        SetFeature(AVX2, ebx);
        SetFeature(SHA, ebx);
        cpuidex(7, 1, &eax, &ebx, &ecx, &edx);
        SetFeature(FZRM, eax);
        SetFeature(FSRS, eax);
        SetFeature(FSRC, eax);
    }
}
#undef SetFeature
#endif

NTSTATUS RtlInitUnicodeStringEx(PUNICODE_STRING DestinationString, PCWSTR SourceString)
{
    const size_t MaxSize = (USHRT_MAX & ~1) - sizeof(WCHAR);

    DestinationString->Length = 0;
    DestinationString->MaximumLength = 0;
    DestinationString->Buffer = (PWCHAR)SourceString;
    if (!SourceString) return STATUS_SUCCESS;

    const size_t Size = strlenW(SourceString) * sizeof(WCHAR);
    if (Size > MaxSize) return STATUS_NAME_TOO_LONG;
    DestinationString->Length = (USHORT)Size;
    DestinationString->MaximumLength = (USHORT)Size + sizeof(WCHAR);
    return STATUS_SUCCESS;
}
static ULONG RtlNtStatusToDosError(NTSTATUS status)
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
        if (status < RtlpRunTable[Entry + 1].BaseCode) {
            ULONG Offset = status - RtlpRunTable[Entry].BaseCode;
            if (Offset >= RtlpRunTable[Entry].RunLength) {
                break;
            }
            Index += (Offset * (ULONG)RtlpRunTable[Entry].CodeSize);
            if (RtlpRunTable[Entry].CodeSize == 1) {
                return RtlpStatusTable[Index];
            }
            return (ULONG)RtlpStatusTable[Index + 1] << 16 | (ULONG)RtlpStatusTable[Index];
        }
        Index += RtlpRunTable[Entry].RunLength * RtlpRunTable[Entry].CodeSize;

        Entry += 1;
    } while (Entry < (sizeof(RtlpRunTable) / sizeof(RUN_ENTRY)));


    if (status >> 16 == 0xC001) {
        return status & 0xFFFF;
    }

    return ERROR_MR_MID_NOT_FOUND;
}
void SetLastNTStatusInternal(ULONG err, bool Error)
{
    PTEB teb = NtGetTeb();
    teb->LastStatusValue = err;
    if(Error) teb->LastErrorValue = RtlNtStatusToDosError(err);
}
inline void SetLastNTStatus(ULONG err)
{
    SetLastNTStatusInternal(err, false);
}
inline void SetLastNTError(ULONG err)
{
    SetLastNTStatusInternal(err, true);
}

PTEB NtGetTeb(void)
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
inline PPEB NtGetPeb(void)
{
    return NtGetTeb()->ProcessEnvironmentBlock;
}
