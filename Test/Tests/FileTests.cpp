#include "../Framework.h"

TEST(File, Size)
{
	EXPECT_TRUE(NativeLib.File.Size);
	EXPECT_EQ(NativeLib.File.Size(nullptr), -1);
	EXPECT_EQ(GetLastError(), ERROR_INVALID_HANDLE);
}