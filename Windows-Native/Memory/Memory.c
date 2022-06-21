#include "Memory.h"

struct Memory Memory = {
	.Create = &Process_Create,
	.Exists = &Process_Exists,
};