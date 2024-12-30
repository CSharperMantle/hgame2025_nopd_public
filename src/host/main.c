#include <fcntl.h>
#include <immintrin.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "callconv.h"
#include "def.h"
#include "ptrace_helper.h"

DEFINE_NOPCALL_HANDLER(nop) {
  (void)child;
  (void)args;
  (void)args_valid;
  (void)new_rip;
#ifdef CSMANTLE
  fprintf(stderr, "%s()\n", __FUNCTION__);
#endif /* CSMANTLE */
  return 0;
}

DEFINE_NOPCALL_HANDLER(gets) {
  (void)new_rip;
  const uintptr_t dest = args[1];
  const uintptr_t n = args[2];
#ifdef CSMANTLE
  fprintf(stderr, "%s(0x%" PRIxPTR ", 0x%" PRIxPTR ")\n", __FUNCTION__, dest, n);
#endif /* CSMANTLE */
  if (!args_valid[1] || !args_valid[2]) {
    return -EINVAL;
  }
  char *const buf = malloc((size_t)n);
  if (buf == NULL) {
    return -ENOMEM;
  }
  if (fgets(buf, (size_t)n, stdin) == NULL) {
    free(buf);
    return -errno;
  }
  ptrace_pokedata_memcpy(child, dest, buf, (size_t)n);
  free(buf);
  return dest;
}

DEFINE_NOPCALL_HANDLER(puts) {
  (void)new_rip;
  const uintptr_t dest = args[1];
#ifdef CSMANTLE
  fprintf(stderr, "%s(0x%" PRIxPTR ")\n", __FUNCTION__, dest);
#endif /* CSMANTLE */
  if (!args_valid[1]) {
    return -EINVAL;
  }
  char buf[8];
  size_t i = 0;
  while (true) {
    ptrace_peekdata_memcpy(child, buf, dest + i, 8);
    for (size_t j = 0; j < 8; j++) {
      if (buf[j] == '\0') {
        putchar('\n');
        return i + j;
      }
      putchar(buf[j]);
    }
    i += 8;
  }
}

static inline __m128i roli(__m128i v, int shamt) {
  return _mm_or_si128(_mm_slli_epi32(v, shamt), _mm_srli_epi32(v, 32 - shamt));
}

DEFINE_NOPCALL_HANDLER(qr) {
  (void)new_rip;
  const uintptr_t dst = args[1];
  const uintptr_t src = args[2];
#ifdef CSMANTLE
  fprintf(stderr, "%s(0x%" PRIxPTR ", 0x%" PRIxPTR ")\n", __FUNCTION__, dst, src);
#endif /* CSMANTLE */
  if (!args_valid[1] || !args_valid[2]) {
    return -EINVAL;
  }
  uint32_t buf[16];
  ptrace_peekdata_memcpy(child, &buf, src, sizeof buf);
  __m128i v0, v1, v2, v3;
  v0 = _mm_loadu_si128((__m128i *)(buf));
  v1 = _mm_loadu_si128((__m128i *)(buf + 4));
  v2 = _mm_loadu_si128((__m128i *)(buf + 8));
  v3 = _mm_loadu_si128((__m128i *)(buf + 12));
  // clang-format off
  v0 = _mm_add_epi32(v0, v1); v3 = _mm_xor_si128(v3, v0); v3 = roli(v3, 16);
  v2 = _mm_add_epi32(v2, v3); v1 = _mm_xor_si128(v1, v2); v1 = roli(v1, 12);
  v0 = _mm_add_epi32(v0, v1); v3 = _mm_xor_si128(v3, v0); v3 = roli(v3, 8);
  v2 = _mm_add_epi32(v2, v3); v1 = _mm_xor_si128(v1, v2); v1 = roli(v1, 7);
  // clang-format on
  _mm_storeu_si128((__m128i *)(buf), v0);
  _mm_storeu_si128((__m128i *)(buf + 4), v1);
  _mm_storeu_si128((__m128i *)(buf + 8), v2);
  _mm_storeu_si128((__m128i *)(buf + 12), v3);
  ptrace_pokedata_memcpy(child, dst, &buf, sizeof buf);
  return 0;
}

DEFINE_NOPCALL_HANDLER(permute) {
  (void)new_rip;
  const uintptr_t dst = args[1];
  const uintptr_t src = args[2];
  const uintptr_t odd_to_even = args[3];
#ifdef CSMANTLE
  printf(
      "%s(0x%" PRIxPTR ", 0x%" PRIxPTR ", 0x%" PRIxPTR ")\n", __FUNCTION__, dst, src, odd_to_even
  );
#endif /* CSMANTLE */
  if (!args_valid[1] || !args_valid[2] || !args_valid[3]) {
    return -EINVAL;
  }
  uint32_t buf[16];
  ptrace_peekdata_memcpy(child, &buf, src, sizeof buf);
  __m128i v0, v1, v2, v3;
  v0 = _mm_loadu_si128((__m128i *)(buf));
  v1 = _mm_loadu_si128((__m128i *)(buf + 4));
  v2 = _mm_loadu_si128((__m128i *)(buf + 8));
  v3 = _mm_loadu_si128((__m128i *)(buf + 12));
  if (!!odd_to_even) {
    v0 = _mm_shuffle_epi32(v0, _MM_SHUFFLE(3, 2, 1, 0));
    v1 = _mm_shuffle_epi32(v1, _MM_SHUFFLE(0, 3, 2, 1));
    v2 = _mm_shuffle_epi32(v2, _MM_SHUFFLE(1, 0, 3, 2));
    v3 = _mm_shuffle_epi32(v3, _MM_SHUFFLE(2, 1, 0, 3));
  } else {
    v0 = _mm_shuffle_epi32(v0, _MM_SHUFFLE(3, 2, 1, 0));
    v1 = _mm_shuffle_epi32(v1, _MM_SHUFFLE(2, 1, 0, 3));
    v2 = _mm_shuffle_epi32(v2, _MM_SHUFFLE(1, 0, 3, 2));
    v3 = _mm_shuffle_epi32(v3, _MM_SHUFFLE(0, 3, 2, 1));
  }
  _mm_storeu_si128((__m128i *)(buf), v0);
  _mm_storeu_si128((__m128i *)(buf + 4), v1);
  _mm_storeu_si128((__m128i *)(buf + 8), v2);
  _mm_storeu_si128((__m128i *)(buf + 12), v3);
  ptrace_pokedata_memcpy(child, dst, &buf, sizeof buf);
  return 0;
}

DEFINE_NOPCALL_HANDLER(pack) {
  (void)new_rip;
  static const uint8_t TAU[] = "i|terh$761f}xi$o";
  const uintptr_t dst = args[1];
  const uintptr_t key = args[2];
  const uintptr_t nonce = args[3];
#ifdef CSMANTLE
  fprintf(
      stderr, "%s(0x%" PRIxPTR ", 0x%" PRIxPTR ", 0x%" PRIxPTR ")\n", __FUNCTION__, dst, key, nonce
  );
#endif /* CSMANTLE */
  if (!args_valid[1] || !args_valid[2] || !args_valid[3]) {
    return -EINVAL;
  }
  union {
    struct {
      uint8_t tau[16];
      uint8_t key[32];
      uint32_t counter;
      uint8_t nonce[12];
    };
    uint8_t as_u8[64];
  } x = {0};
  memcpy(x.tau, TAU, sizeof x.tau);
  for (size_t i = 0; i < sizeof x.tau; i++) {
    x.tau[i] -= 4;
  }
  ptrace_peekdata_memcpy(child, x.key, key, 32);
  ptrace_peekdata_memcpy(child, x.nonce, nonce, 12);
  x.counter = 0;
#ifdef CSMANTLE
  printf("key: ");
  for (size_t i = 0; i < sizeof x.key; i++) {
    printf("%02hhx", x.key[i]);
  }
  putchar('\n');
  printf("nonce: ");
  for (size_t i = 0; i < sizeof x.nonce; i++) {
    printf("%02hhx", x.nonce[i]);
  }
  putchar('\n');
#endif
  ptrace_pokedata_memcpy(child, dst, x.as_u8, sizeof x.as_u8);
  return 0;
}

DEFINE_NOPCALL_HANDLER(blkadd) {
  (void)new_rip;
  const uintptr_t dst = args[1];
  const uintptr_t src = args[2];
  const uintptr_t state = args[3];
#ifdef CSMANTLE
  fprintf(
      stderr, "%s(0x%" PRIxPTR ", 0x%" PRIxPTR ", 0x%" PRIxPTR ")\n", __FUNCTION__, dst, src, state
  );
#endif /* CSMANTLE */
  if (!args_valid[1] || !args_valid[2] || !args_valid[3]) {
    return -EINVAL;
  }

  uint32_t x[16], y[16];
  ptrace_peekdata_memcpy(child, x, src, sizeof x);
  ptrace_peekdata_memcpy(child, y, state, sizeof y);
  for (size_t i = 0; i < 16; i++) {
    x[i] += y[i];
  }
  ptrace_pokedata_memcpy(child, dst, x, sizeof x);
  return 0;
}

DEFINE_NOPCALL_HANDLER(check) {
  (void)new_rip;
  const uintptr_t cipher = args[1];
  const uintptr_t cipher_len = args[2];
  const uintptr_t input = args[3];
#ifdef CSMANTLE
  printf(
      "%s(0x%" PRIxPTR ", 0x%" PRIxPTR ", 0x%" PRIxPTR ")\n",
      __FUNCTION__,
      cipher,
      cipher_len,
      input
  );
#endif /* CSMANTLE */
  if (!args_valid[1] || !args_valid[2] || !args_valid[3]) {
    return -EINVAL;
  }

  uint8_t *const cipher_buf = malloc((size_t)cipher_len);
  if (cipher_buf == NULL) {
    return -ENOMEM;
  }
  uint8_t *const input_buf = malloc((size_t)cipher_len);
  if (input_buf == NULL) {
    free(cipher_buf);
    return -ENOMEM;
  }
  ptrace_peekdata_memcpy(child, cipher_buf, cipher, (size_t)cipher_len);
  ptrace_peekdata_memcpy(child, input_buf, input, (size_t)cipher_len);
  const bool retval = memcmp(cipher_buf, input_buf, (size_t)cipher_len) == 0;
  free(cipher_buf);
  free(input_buf);
  return retval;
}

DEFINE_NOPCALL_HANDLER(get_iv) {
  (void)child;
  (void)args;
  (void)args_valid;
  (void)new_rip;
#ifdef CSMANTLE
  printf("%s()\n", __FUNCTION__);
#endif /* CSMANTLE */
  return 0x61C88646;
}

DEFINE_NOPCALL_HANDLER(skip_128b) {
  (void)child;
  (void)args;
  (void)args_valid;
#ifdef CSMANTLE
  printf("%s()\n", __FUNCTION__);
#endif /* CSMANTLE */
  *new_rip += 128;
  return 0;
}

static int (*const NOPCALL_HANDLERS[LEN_NopcallCode])(
    pid_t, const uintptr_t[128], const bool[128], uintptr_t *restrict
) = {
    [NOP_nop] = NAMEOF_NOPCALL_HANDLER(nop),
    [NOP_gets] = NAMEOF_NOPCALL_HANDLER(gets),
    [NOP_puts] = NAMEOF_NOPCALL_HANDLER(puts),
    [NOP_qr] = NAMEOF_NOPCALL_HANDLER(qr),
    [NOP_permute] = NAMEOF_NOPCALL_HANDLER(permute),
    [NOP_pack] = NAMEOF_NOPCALL_HANDLER(pack),
    [NOP_blkadd] = NAMEOF_NOPCALL_HANDLER(blkadd),
    [NOP_check] = NAMEOF_NOPCALL_HANDLER(check),
    [NOP_get_iv] = NAMEOF_NOPCALL_HANDLER(get_iv),
    [NOP_skip_128b] = NAMEOF_NOPCALL_HANDLER(skip_128b),
};

[[gnu::noinline]]
static int parent(pid_t child) {
  static NopcallMarker_t begin_marker;
  static uintptr_t args_value[128];
  static bool args_valid[128];
  static size_t n_args;
  static struct user_regs_struct precall_regs, postcall_regs;

  waitpid(child, 0, 0);
  ptrace(PTRACE_SETOPTIONS, child, NULL, PTRACE_O_EXITKILL);
  while (true) {
    if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0) {
      break;
    }
    waitpid(child, NULL, 0);

    ptrace(PTRACE_GETREGS, child, NULL, &precall_regs);
    ptrace_peektext_memcpy(
        child,
        begin_marker.as_u8,
        precall_regs.rip - 2 /* syscall */ - sizeof(begin_marker.as_u8),
        sizeof(begin_marker.as_u8)
    );
    bool nopcall_valid = false;
    if (is_nopcall_marker(&begin_marker) && begin_marker.disp8 == 0x7f) {
      memset(args_valid, 0, sizeof(args_valid));
      n_args = 0;
      while (true) {
        NopcallMarker_t m;
        ptrace_peektext_memcpy(
            child, m.as_u8, precall_regs.rip + sizeof(m.as_u8) * n_args, sizeof(m.as_u8)
        );
        if (!is_nopcall_marker(&m) || m.disp8 == 0x7e) {
          break;
        }
        const uint8_t arg_idx = (m.disp8 - 1) % 128;
        if (m.sib.stride == 0b00) {
          args_value[arg_idx] = nopcall_get_reg_val(&precall_regs, nopcall_marker_get_idx_base(&m));
        } else {
          uintptr_t val;
          ptrace_peekdata_memcpy(
              child, &val, precall_regs.rsp + 8 * nopcall_marker_get_idx_base(&m), sizeof val
          );
          args_value[arg_idx] = val;
        }
#ifdef CSMANTLE
        printf(
            "0x%016llx arg[%hhu] S=%hhu V=0x%016lx\n",
            precall_regs.rip + sizeof(m.as_u8) * n_args,
            arg_idx,
            m.sib.stride,
            args_value[arg_idx]
        );
#endif
        args_valid[arg_idx] = true;
        n_args++;
        nopcall_valid = true;
      }
    }

    uintptr_t retval = -ENOSYS;
    uintptr_t new_rip = precall_regs.rip;
    if (nopcall_valid && args_valid[0]) {
      const uintptr_t call_number = args_value[0];
#ifdef CSMANTLE
      printf("nopcall %lu\n", call_number);
#endif
      if (call_number < LEN_NopcallCode && NOPCALL_HANDLERS[call_number] != NULL) {
        retval = NOPCALL_HANDLERS[call_number](child, args_value, args_valid, &new_rip);
      }
      precall_regs.orig_rax = UINT64_MAX;
      ptrace(PTRACE_SETREGS, child, NULL, &precall_regs);
    }

    ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    waitpid(child, NULL, 0);

    if (nopcall_valid) {
      ptrace(PTRACE_GETREGS, child, NULL, &postcall_regs);
      postcall_regs.rax = retval;
      postcall_regs.rip = new_rip;
      ptrace(PTRACE_SETREGS, child, NULL, &postcall_regs);
    }
  }
  return 0;
}

static inline int child(char *argv[]) {
  ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  if (execv(argv[1], &argv[1]) < 0) {
    perror("execv");
    return -1;
  }
  __builtin_unreachable();
}

static pid_t pid = -1;

static void parent_wrapper(void) {
  if (pid > 0) {
    parent(pid);
  }
}

[[gnu::constructor]]
static void init_0(void) {
  if (atexit(parent_wrapper) != 0) {
    abort();
  }
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <path-to-game> [args...]\n", argv[0]);
    return EXIT_FAILURE;
  }
  pid = fork();
  switch (pid) {
    case -1: perror("fork"); return EXIT_FAILURE;
    case 0: return child(argv);
    default: return EXIT_SUCCESS;
  }
}
