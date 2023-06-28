
#include "ripemd160.hpp"
#include <benchmark/benchmark.h>

static void ripemd160_compress(benchmark::State& state)
{
    uint32_t ctx[5]{};
    uint32_t xxx[16]{};

    for (auto _ : state)
        rmd160_compress(ctx, xxx);
}

BENCHMARK(ripemd160_compress);

BENCHMARK_MAIN();