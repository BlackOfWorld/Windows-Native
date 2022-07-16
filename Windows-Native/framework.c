#include "framework.h"

#define CPU_FEATURE_FSRM       1 << 4
#define CPU_FEATURE_SGX        1 << 2
#define CPU_FEATURE_AVX        1 << 28
#define CPU_FEATURE_AVX2       1 << 5
#define CPU_FEATURE_RDRAND     1 << 30
#define CPU_FEATURE_AES        1 << 25
#define CPU_FEATURE_SSE        1 << 25
#define CPU_FEATURE_SSE2       1 << 26
#define CPU_FEATURE_SHA        1 << 29
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
	if(maxFunc >= 1)
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
	}
}
#undef SetFeature
#endif