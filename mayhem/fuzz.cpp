#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" int istrcmp(const char *a, const char *b);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);

    istrcmp(provider.ConsumeRandomLengthString().c_str(),
            provider.ConsumeRandomLengthString().c_str());

    return 0;
}