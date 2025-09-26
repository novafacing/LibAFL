#include <cstddef>
#include <cstdint>

#ifdef _WIN32
#define FUZZ_EXPORT extern "C" __declspec(dllexport)
#else
#define FUZZ_EXPORT extern "C"
#endif

/// A buggy decoder function
void DecodeInput(const uint8_t *data, size_t size) {
  if (size < 4) return;
  if (data[0] == 'B' && data[1] == 'U' && data[2] == 'G' && data[3] == '!') {
    volatile int *p = nullptr;
    *p = 0;
  }
}

FUZZ_EXPORT int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  DecodeInput(data, size);
  return 0;
}