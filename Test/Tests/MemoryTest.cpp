#include "../Framework.h"
TEST(Memory, AllocateAndFree_Heap)
{
	EXPECT_TRUE(NativeLib.Memory.AllocateHeap) << ERROR_MSG("AllocateHeap function does not exist!");
	EXPECT_TRUE(NativeLib.Memory.FreeHeap) << ERROR_MSG("FreeHeap function does not exist!");

	PVOID Buffers[0x100] = {nullptr};
	for (auto i = 0; i < 0x100; i++)
	{
		Buffers[i] = NativeLib.Memory.AllocateHeap(i % 16, FALSE);
		ASSERT_TRUE(Buffers[i]) << ERROR_MSG("Failed to allocate heap!");
	}
	for (const auto& buff : Buffers)
		ASSERT_TRUE(NativeLib.Memory.FreeHeap(buff)) << ERROR_MSG("Failed to free heap!");
}
TEST(Memory, AllocateAndFree_Virtual)
{
	EXPECT_TRUE(NativeLib.Memory.AllocateVirtual) << ERROR_MSG("AllocateVirtual function does not exist!");
	EXPECT_TRUE(NativeLib.Memory.FreeVirtual) << ERROR_MSG("FreeVirtual function does not exist!");
	for (auto i = 0; i < 0x100; i++)
	{
		DWORD size = i % 16 + 1;
		auto address = NativeLib.Memory.AllocateVirtual(size, MEM_RESERVE, PAGE_READONLY);
		ASSERT_TRUE(address) << ERROR_MSG("Failed to allocate virtual!");
		ASSERT_TRUE(NativeLib.Memory.FreeVirtual(address, size, MEM_RELEASE)) << ERROR_MSG("Failed to free virtual!");
	}
}
TEST(Memory, GetCurrentHeap)
{
	EXPECT_TRUE(NativeLib.Memory.GetCurrentHeap) << ERROR_MSG("GetCurrentHeap function does not exist!");
	EXPECT_EQ(NativeLib.Memory.GetCurrentHeap(), GetProcessHeap());
}
