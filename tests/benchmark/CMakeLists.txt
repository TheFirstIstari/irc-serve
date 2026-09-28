add_executable(bench_mem footprint.c)
add_executable(bench_throughput throughput.c)

# Benchmarks exercise real parser code from irc_core.
target_link_libraries(bench_throughput PRIVATE irc_core)

# Ensure assert() checks are not compiled out in Release builds used by CI.
target_compile_options(bench_mem PRIVATE $<$<CONFIG:Release>:-UNDEBUG>)
target_compile_options(bench_throughput PRIVATE $<$<CONFIG:Release>:-UNDEBUG>)

# Registered as CTest tests with the Benchmark label whenever this
# subdirectory is built (which is gated on BUILD_BENCHMARK at the top-level),
# so BUILD_BENCHMARK=ON produces real, runnable labeled benchmark tests --
# not empty green gates.
add_test(NAME BenchmarkMemory COMMAND bench_mem)
set_tests_properties(BenchmarkMemory PROPERTIES LABELS Benchmark)

add_test(NAME BenchmarkThroughput COMMAND bench_throughput)
set_tests_properties(BenchmarkThroughput PROPERTIES LABELS Benchmark)