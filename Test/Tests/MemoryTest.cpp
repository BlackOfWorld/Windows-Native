#include "../Framework.h"
TEST(Memory, AllocateAndFree)
{
	PVOID Buffers[0x100] = {nullptr};
	for (auto i = 0; i < 0x100; i++)
	{
		Buffers[i] = NativeLib.Memory.Allocate(i % 16, FALSE);
		ASSERT_TRUE(Buffers[i]);
	}
	for (const auto& buff : Buffers)
		ASSERT_TRUE(NativeLib.Memory.Free(buff));
}
TEST(Memory, GetCurrentHeap)
{
	EXPECT_TRUE(NativeLib.Memory.GetCurrentHeap);
	EXPECT_EQ(NativeLib.Memory.GetCurrentHeap(), GetProcessHeap());
}
