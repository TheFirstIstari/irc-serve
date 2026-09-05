add_executable(bench_mem footprint.c)
add_executable(bench_throughput throughput.c)

# Ensure assert() checks are not compiled out in Release builds used by CI.
target_compile_options(bench_mem PRIVATE $<$<CONFIG:Release>:-UNDEBUG>)
target_compile_options(bench_throughput PRIVATE $<$<CONFIG:Release>:-UNDEBUG>)

option(REGISTER_BENCHMARK_TESTS "Register benchmarks as CTest tests" OFF)

if(REGISTER_BENCHMARK_TESTS)
  add_test(NAME BenchmarkMemory COMMAND bench_mem)
  set_tests_properties(BenchmarkMemory PROPERTIES LABELS Benchmark)

  add_test(NAME BenchmarkThroughput COMMAND bench_throughput)
  set_tests_properties(BenchmarkThroughput PROPERTIES LABELS Benchmark)
endif()
