#pragma once
#include "General.h"

typedef enum LoaderFlags
{
	File,
	Memory,
	NoLink
};
void API_Init(void);

extern struct LIBRARY Library;
