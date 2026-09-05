add_executable(bench_mem footprint.c)
add_executable(bench_throughput throughput.c)

add_test(NAME BenchmarkMemory COMMAND bench_mem)
set_tests_properties(BenchmarkMemory PROPERTIES LABELS Benchmark)

add_test(NAME BenchmarkThroughput COMMAND bench_throughput)
set_tests_properties(BenchmarkThroughput PROPERTIES LABELS Benchmark)
