#include "framework.h"

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
    uint32_t maxFunc = eax;
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

    size_t Size = strlenW(SourceString) * sizeof(WCHAR);
    if (Size > MaxSize) return STATUS_NAME_TOO_LONG;
    DestinationString->Length = (USHORT)Size;
    DestinationString->MaximumLength = (USHORT)Size + sizeof(WCHAR);
    return STATUS_SUCCESS;
}
