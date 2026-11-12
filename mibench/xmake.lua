-- Copyright Microsoft and CHERIoT Contributors.
-- SPDX-License-Identifier: MIT

set_project("CHERIoT mibench benchmarks");
sdkdir = "../cheriot-rtos/sdk"
includes(sdkdir)
set_toolchains("cheriot-clang")

option("board")
    set_default("sail")

-- Helper to add a C++ test
function test(name)
    compartment(name .. "_test")
         -- Allow allocating an effectively unbounded amount of memory (more than exists)
         add_defines("MALLOC_QUOTA=1000000")

         add_files(name .. "-test.cc")
end

test("mibench_crc32")
test("mibench_bitcount")
test("mibench_dijkstra")
test("mibench_qsort")
test("mibench_sha")
test("mibench_stringsearch")
test("mibench_adpcm")
test("mibench_aes")

-- TODO: normal deps + minimise
includes(path.join(sdkdir, "lib/atomic"),
         path.join(sdkdir, "lib/cxxrt"),
         path.join(sdkdir, "lib/freestanding"),
         path.join(sdkdir, "lib/string"),
         path.join(sdkdir, "lib/crt"),
         path.join(sdkdir, "lib/thread_pool"))

-- Compartment for the test entry point.
compartment("test_runner")
    add_files("test-runner.cc")

-- Firmware image for the test suite.
firmware("test-suite")
    -- Main entry points
    add_deps("test_runner", "thread_pool")
    -- Helper libraries
    add_deps("freestanding", "string", "crt", "cxxrt", "atomic", "debug")
    -- Tests
    add_deps("mibench_crc32_test")
    add_deps("mibench_bitcount_test")
    add_deps("mibench_dijkstra_test")
    add_deps("mibench_qsort_test")
    add_deps("mibench_sha_test")
    add_deps("mibench_stringsearch_test")
    add_deps("mibench_adpcm_test")
    add_deps("mibench_aes_test")
    -- Set the thread entry point to the test runner.
    on_load(function(target)
        target:values_set("board", "$(board)")
        target:values_set("threads", {
            {
                compartment = "test_runner",
                priority = 2,
                entry_point = "run_tests",
                stack_size = 0x400,
                trusted_stack_frames = 5
            },
            {
                compartment = "thread_pool",
                priority = 1,
                entry_point = "thread_pool_run",
                stack_size = 0x400,
                trusted_stack_frames = 5
            },
            {
                compartment = "thread_pool",
                priority = 1,
                entry_point = "thread_pool_run",
                stack_size = 0x400,
                trusted_stack_frames = 5
            }
        }, {expand = false})
    end)
