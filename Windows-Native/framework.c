#include <intrin.h>
int cpu_fsrm = 0;
#if defined(_WIN32) && (defined(_M_IX86) || defined(_M_X64))
void cpu_detect_features(void)
{
	int cpuid[4];
	__cpuid(cpuid, 7);
	cpu_fsrm = (cpuid[3] & 1 << 4) != 0;
}
#else
void cpu_detect_features(void) {}
#endif