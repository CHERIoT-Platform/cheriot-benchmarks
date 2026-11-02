// Copyright Microsoft and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include "tests.hh"
#include <compartment.h>
#include <platform-rdcycle.h>
#include <priv/riscv.h>
#include <simulator.h>

using namespace CHERI;

namespace
{
	/// Have we detected a crash in any of the compartments?
	volatile bool crashDetected = false;

	/**
	 * Call `fn` and log a message informing the user how long it took.
	 */
	void run_timed(const char *msg, auto &&fn)
	{
		bool failed      = false;
		int  startCycles = rdcycle();
		if constexpr (std::is_same_v<std::invoke_result_t<decltype(fn)>, void>)
		{
			fn();
		}
		else
		{
			failed = (fn() != 0);
		}
		int cycles = rdcycle();

		if (failed)
		{
			debug_log("{} failed", msg);
			crashDetected = true;
		}
		else
		{
			debug_log("{} finished in {} cycles", msg, cycles - startCycles);
		}

	}
} // namespace

extern "C" enum ErrorRecoveryBehaviour
compartment_error_handler(struct ErrorState *frame, size_t mcause, size_t mtval)
{
	debug_log("mcause: {}, pcc: {}, cra: {}",
	          mcause,
	          frame->pcc,
	          frame->get_register_value<RegisterNumber::CRA>());
	auto [reg, cause] = CHERI::extract_cheri_mtval(mtval);
	debug_log("Error {} in register {}", reg, cause);
	if (mcause == priv::MCAUSE_ILLEGAL_INSTRUCTION)
	{
		debug_log("Test failure in test runner");
		simulation_exit(1);
	}
	return ErrorRecoveryBehaviour::InstallContext;
}

/**
 * Test suite entry point.  Runs all of the tests that we have defined.
 */
[[cheriot::interrupt_state(disabled)]]
void __cheri_compartment("test_runner") run_tests()
{
	run_timed("All tests", []() {
		run_timed("MiBench CRC32", test_mibench_crc32);
		run_timed("MiBench bitcount", test_mibench_bitcount);
		run_timed("MiBench dijkstra", test_mibench_dijkstra);
		run_timed("MiBench qsort", test_mibench_qsort);
		run_timed("MiBench SHA", test_mibench_sha);
		run_timed("MiBench stringsearch", test_mibench_stringsearch);
		run_timed("MiBench adpcm", test_mibench_adpcm);
		run_timed("MiBench AES", test_mibench_aes);
	});

	TEST(crashDetected == false, "One or more tests failed");

	simulation_exit();
}
