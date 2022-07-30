#include "../Framework.h"

TEST(File, Create)
{
	NativeLib.File.Create((wchar_t*)L"TestFile.txt", GENERIC_WRITE, FILE_SHARE_WRITE, CREATE_NEW, FILE_ATTRIBUTE_NORMAL);
}

TEST(File, Size)
{
	EXPECT_TRUE(NativeLib.File.Size);
	EXPECT_EQ(NativeLib.File.Size(nullptr), -1);
	EXPECT_EQ(GetLastError(), ERROR_INVALID_HANDLE);
}