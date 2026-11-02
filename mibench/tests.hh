// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <cdefs.h>
#include <debug.hh>
#include <thread.h>

__cheri_compartment("mibench_crc32_test") void test_mibench_crc32();
__cheri_compartment("mibench_bitcount_test") void test_mibench_bitcount();
__cheri_compartment("mibench_dijkstra_test") void test_mibench_dijkstra();
__cheri_compartment("mibench_qsort_test") void test_mibench_qsort();
__cheri_compartment("mibench_sha_test") void test_mibench_sha();
__cheri_compartment("mibench_stringsearch_test") void test_mibench_stringsearch();
__cheri_compartment("mibench_adpcm_test") void test_mibench_adpcm();
__cheri_compartment("mibench_aes_test") void test_mibench_aes();

using Test = ConditionalDebug<true,
#ifdef TEST_NAME
                              TEST_NAME " test"
#else
                              "Test runner"
#endif
                              >;

template<typename... Args>
void debug_log(const char *fmt, Args... args)
{
	Test::log(fmt, args...);
}

#define TEST(cond, msg, ...) Test::Invariant((cond), msg, ##__VA_ARGS__)

/**
 * Helper to sleep for a number of ticks and not report the sleep time.
 */
inline Ticks sleep(Ticks ticks)
{
	Timeout t{ticks};
	thread_sleep(&t);
	return t.elapsed;
};
