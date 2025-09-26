#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>

#ifdef _WIN32
#define FUZZ_EXPORT extern "C" __declspec(dllexport)
#else
#define FUZZ_EXPORT extern "C"
#endif

// A small, intentionally buggy mini-protocol parser to exercise a fuzzer.
// Format:
//  Bytes 0-1: Constant ASCII header "CT"
//  Bytes 2-3: 16-bit LE magic value 0x1337
//  Then a stream of TLV records until end:
//     [Type:1][Len:1][Payload:Len]
//  Types:
//   'A' Allocate  : payload[0]=slot(0-7), payload[1]=size (1..200), rest ignored (content)
//   'W' Write     : payload[0]=slot, rest=bytes to write (may trigger off-by-one) 
//   'C' Clone     : payload[0]=src, payload[1]=dst (shares pointer, refcount bug for size==0x40)
//   'F' Free      : payload[0]=slot, last payload byte controls dangling pointer condition
//   'X' CheckXor  : if cumulative xor of all payload bytes so far == 0x42, trigger DangerousFinalize()
//   'K' CheckSum  : 16-bit little-endian expected sum of bytes so far (excluding header). If matches, run HiddenOverflow()
// Vulnerabilities:
//  - Double free: 'F' with last payload byte == 0xAA leaves dangling pointer; later DangerousFinalize() frees again.
//  - Refcount bug: Clone of an object of size 0x40 fails to bump refcount -> UAF/double free sequence possible.
//  - Off-by-one: 'W' writes (len-1) bytes but if exactly equals stored size, also writes a 0 terminator past end.
//  - HiddenOverflow(): crafted condition performs memmove with attacker-controlled length exceeding destination.
// These combined gates (header+magic+xor/sum) make the crash non-trivial but reachable.

struct Obj {
  uint8_t *data;
  size_t size;
  int refcount;
};

static Obj g_objs[8];
static uint32_t g_total_sum = 0; // sum of payload bytes
static uint8_t g_total_xor = 0;  // xor of payload bytes

static void DangerousFinalize() {
  // Intentionally attempts to free dangling pointers (refcount == 0 but data not null)
  for (int i = 0; i < 8; i++) {
    if (g_objs[i].data && g_objs[i].refcount == 0) {
      // Potential double free
      free(g_objs[i].data);
      g_objs[i].data = nullptr; // This time we null it.
    }
  }
}

static void HiddenOverflow() {
  // Find two consecutive allocated slots and perform an unsafe memmove.
  for (int i = 0; i < 7; i++) {
    if (g_objs[i].data && g_objs[i + 1].data) {
      size_t src_sz = g_objs[i + 1].size;
      size_t dst_sz = g_objs[i].size;
      // Bug: length is dst_sz + src_sz (can exceed dst buffer) if dst_sz is a multiple of 16
      if ((dst_sz & 0xF) == 0) {
        size_t len = dst_sz + src_sz; // overflow read/write possibility
        // Overlapping move with excessive length → heap metadata corruption potential
        memmove(g_objs[i].data, g_objs[i + 1].data, len);
      }
      return;
    }
  }
}

static void ResetState() {
  for (int i = 0; i < 8; i++) {
    if (g_objs[i].data) {
      free(g_objs[i].data);
      g_objs[i].data = nullptr;
    }
    g_objs[i].size = 0;
    g_objs[i].refcount = 0;
  }
  g_total_sum = 0;
  g_total_xor = 0;
}

static void HandleAllocate(const uint8_t *payload, size_t len) {
  if (len < 2) return;
  int slot = payload[0] & 7;
  size_t sz = payload[1];
  if (sz == 0 || sz > 200) return;
  if (g_objs[slot].data) return; // already allocated
  uint8_t *buf = (uint8_t*)malloc(sz);
  if (!buf) return;
  // Initialize with some pattern
  for (size_t i = 0; i < sz; i++) buf[i] = (uint8_t)(payload[i % len] + i);
  g_objs[slot].data = buf;
  g_objs[slot].size = sz;
  g_objs[slot].refcount = 1;
}

static void HandleWrite(const uint8_t *payload, size_t len) {
  if (len < 2) return;
  int slot = payload[0] & 7;
  Obj &o = g_objs[slot];
  if (!o.data) return;
  size_t to_write = len - 1;
  if (to_write > o.size) to_write = o.size; // clamp
  // Bug: if to_write equals original size, we still write a trailing null (off-by-one)
  for (size_t i = 0; i < to_write; i++) {
    o.data[i] = payload[1 + i];
  }
  if (to_write == o.size) {
    // Off-by-one write
    o.data[o.size] = 0; // buffer overflow by 1
  }
}

static void HandleClone(const uint8_t *payload, size_t len) {
  if (len < 2) return;
  int src = payload[0] & 7;
  int dst = payload[1] & 7;
  if (src == dst) return;
  if (!g_objs[src].data || g_objs[dst].data) return;
  g_objs[dst] = g_objs[src];
  // Bug: Fails to bump refcount for size == 0x40, enabling premature double free
  if (g_objs[dst].size != 0x40) {
    g_objs[src].refcount++;
    g_objs[dst].refcount = g_objs[src].refcount;
  }
}

static void HandleFree(const uint8_t *payload, size_t len) {
  if (len < 1) return;
  int slot = payload[0] & 7;
  Obj &o = g_objs[slot];
  if (!o.data) return;
  if (o.refcount > 1) {
    o.refcount--; // shared
    return;
  }
  free(o.data);
  // Bug: If last byte == 0xAA, leave dangling pointer (for later double free in DangerousFinalize)
  if (!(len >= 2 && payload[len - 1] == 0xAA)) {
    o.data = nullptr;
  }
  o.size = 0;
  o.refcount = 0;
}

static void HandleCheckXor() {
  if (g_total_xor == 0x42) {
    DangerousFinalize();
  }
}

static void HandleCheckSum(const uint8_t *payload, size_t len) {
  if (len < 2) return;
  uint16_t expect = (uint16_t)payload[0] | ((uint16_t)payload[1] << 8);
  if ((g_total_sum & 0xFFFF) == expect) {
    HiddenOverflow();
  }
}

static void ParseTLV(const uint8_t *buf, size_t size, size_t off) {
  while (off + 2 <= size) {
    uint8_t t = buf[off];
    uint8_t l = buf[off + 1];
    off += 2;
    if (off + l > size) break; // truncated
    const uint8_t *payload = buf + off;

    // Update global aggregates
    for (size_t i = 0; i < l; i++) {
      g_total_sum += payload[i];
      g_total_xor ^= payload[i];
    }

    switch (t) {
      case 'A': HandleAllocate(payload, l); break;
      case 'W': HandleWrite(payload, l); break;
      case 'C': HandleClone(payload, l); break;
      case 'F': HandleFree(payload, l); break;
      case 'X': HandleCheckXor(); break;
      case 'K': HandleCheckSum(payload, l); break;
      default: break; // unknown type ignored
    }
    off += l;
  }
}

void DecodeInput(const uint8_t *data, size_t size) {
  if (size < 6) return;
  if (data[0] != 'C' || data[1] != 'T') return;
  uint16_t magic = (uint16_t)data[2] | ((uint16_t)data[3] << 8);
  if (magic != 0x1337) return;

  ResetState();
  ParseTLV(data, size, 4);

  // A final implicit check to sometimes trigger DangerousFinalize again
  if ((g_total_sum & 0xFF) == 0xAB) {
    DangerousFinalize();
  }
}

FUZZ_EXPORT int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  DecodeInput(data, size);
  return 0;
}