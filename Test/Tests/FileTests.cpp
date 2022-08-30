#include "../Framework.h"

const char testString[] = "Hello from Windows-Native!";

TEST(File, Create)
{
    EXPECT_EQ(NativeLib.File.Create(L"\0", 0, 0, 0, 0), INVALID_HANDLE_VALUE);
    HANDLE hFile = NativeLib.File.Create(L"TestFile.txt", FILE_GENERIC_WRITE, FILE_SHARE_WRITE, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL);
    EXPECT_NE(hFile, INVALID_HANDLE_VALUE);
    EXPECT_EQ(NativeLib.File.Close(hFile), true);
}

TEST(File, Write)
{
    HANDLE hFile = NativeLib.File.Create(L"TestFile.txt", FILE_GENERIC_WRITE, FILE_SHARE_WRITE, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL);
    EXPECT_NE(hFile, INVALID_HANDLE_VALUE);
    EXPECT_EQ(NativeLib.File.Write(hFile, testString, sizeof(testString), NULL, NULL), TRUE);
    EXPECT_EQ(NativeLib.File.Close(hFile), true);
}

TEST(File, Read)
{
    HANDLE hFile = NativeLib.File.Create(L"TestFile.txt", FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL);
    EXPECT_NE(hFile, INVALID_HANDLE_VALUE);

    char* buff = new char[1024];
    memset(buff, 0, 1024);
    EXPECT_EQ(NativeLib.File.Read(hFile, buff, sizeof(testString), NULL, NULL), TRUE);
    EXPECT_STREQ(buff, testString);
    delete[] buff;

    EXPECT_EQ(NativeLib.File.Close(hFile), true);
}

TEST(File, Size)
{
    EXPECT_TRUE(NativeLib.File.Size);
    EXPECT_EQ(NativeLib.File.Size(nullptr), INVALID_FILE_SIZE);
    HANDLE hFile = NativeLib.File.Create(L"TestFile.txt", FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL);
    EXPECT_NE(hFile, INVALID_HANDLE_VALUE);
    EXPECT_EQ(NativeLib.File.Size(hFile), sizeof(testString));
    EXPECT_EQ(NativeLib.File.Close(hFile), true);
}

TEST(File, Delete)
{
     EXPECT_EQ(NativeLib.File.Delete(L"TestFile.txt"), true);
     HANDLE hFile = NativeLib.File.Create(L"TestFile.txt", FILE_GENERIC_READ, FILE_SHARE_READ, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL);
     EXPECT_EQ(NativeLib.File.Delete(L"TestFile.txt"), true);
     EXPECT_EQ(NativeLib.File.Close(hFile), true);
 }