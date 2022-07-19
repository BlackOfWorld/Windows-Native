#include "../Framework.h"
TEST(Memory, AllocateAndFree_Heap)
{
	PVOID Buffers[0x100] = {nullptr};
	for (auto i = 0; i < 0x100; i++)
	{
		Buffers[i] = NativeLib.Memory.AllocateHeap(i % 16, FALSE);
		ASSERT_TRUE(Buffers[i]);
	}
	for (const auto& buff : Buffers)
		ASSERT_TRUE(NativeLib.Memory.FreeHeap(buff));
}
TEST(Memory, AllocateAndFree_Virtual)
{
	for (auto i = 0; i < 0x100; i++)
	{
		DWORD size = i % 16 + 1;
		auto address = NativeLib.Memory.AllocateVirtual(size, MEM_RESERVE, PAGE_READONLY);
		ASSERT_TRUE(address);
		ASSERT_TRUE(NativeLib.Memory.FreeVirtual(address, size, MEM_RELEASE));
	}
}
TEST(Memory, GetCurrentHeap)
{
	EXPECT_TRUE(NativeLib.Memory.GetCurrentHeap);
	EXPECT_EQ(NativeLib.Memory.GetCurrentHeap(), GetProcessHeap());
}
