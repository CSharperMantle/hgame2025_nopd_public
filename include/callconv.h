#ifndef CALLCONV_H_INCLUDED_
#define CALLCONV_H_INCLUDED_

#include "def.h"
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/user.h>

#define NAMEOF_NOPCALL_HANDLER(name_) handle_##name_

#define DEFINE_NOPCALL_HANDLER(name_)                                                              \
  static int NAMEOF_NOPCALL_HANDLER(name_)(                                                        \
      pid_t child,                                                                                 \
      const uintptr_t args[128],                                                                   \
      const bool args_valid[128],                                                                  \
      uintptr_t *restrict new_rip                                                                  \
  )

typedef enum NopcallCode_ {
  NOP_nop = 0,
  NOP_gets,
  NOP_puts,
  NOP_qr,
  NOP_permute,
  NOP_pack,
  NOP_blkadd,
  NOP_check,
  NOP_get_iv,
  NOP_skip_128b,

  LEN_NopcallCode,
} NopcallCode_t;

typedef union NopcallMarker_ {
  struct {
    struct {
      uint8_t rex_b : 1;
      uint8_t rex_i : 1;
      uint8_t fixed0 : 6;
    } prefix;
    uint8_t opcode[2];
    struct {
      uint8_t rm : 3;
      uint8_t reg : 3;
      uint8_t mod : 2;
    } modrm;
    struct {
      uint8_t base : 3;
      uint8_t index : 3;
      uint8_t stride : 2;
    } sib;
    uint8_t disp8;
  };
  uint8_t as_u8[6];
} NopcallMarker_t;

[[gnu::always_inline]]
static inline long nopcall_1f_0r(long fake_number, uintptr_t fake_arg0, NopcallCode_t real_number) {
  long result;
  // clang-format off
  asm volatile (
    "mov %1, %%rax" ASM_LE
    "mov %2, %%rdi" ASM_LE
    "mov %3, %%rbx" ASM_LE
    "nopq 0x7f(%%rax, %%rax, 1)" ASM_LE
    "syscall" ASM_LE
    "nopq 0x1(%%rbx, %%rax, 1)" ASM_LE
    "nopq 0x7e(%%rax, %%rax, 1)" ASM_LE
    "mov %%rax, %0" ASM_LE
    : "=rm" (result)
    : "g" (fake_number),
      "rm" (fake_arg0),
      "rm" ((uintptr_t)real_number)
    : "rax", "rcx", "rbx", "rdi", "r11", "memory");
  // clang-format on
  if (result < 0) {
    errno = -result;
    return -1;
  }
  return result;
}

[[gnu::always_inline]]
static inline long nopcall_1f_3r(
    long fake_number,
    uintptr_t fake_arg0,
    NopcallCode_t real_number,
    uintptr_t real_arg0,
    uintptr_t real_arg1,
    uintptr_t real_arg2
) {
  long result;
  // clang-format off
  asm volatile (
    "mov %1, %%rax" ASM_LE
    "mov %2, %%rdi" ASM_LE
    "mov %3, %%rbx" ASM_LE
    "mov %4, %%r9" ASM_LE
    "pushq %5" ASM_LE
    "pushq %6" ASM_LE
    "nopq 0x7f(%%rax, %%rax, 1)" ASM_LE
    "syscall" ASM_LE
    "nopq 0x3(%%rcx, %%rax, 2)" ASM_LE
    "nopq 0x1(%%rbx, %%rax, 1)" ASM_LE
    "nopq 0x4(%%rax, %%rax, 2)" ASM_LE
    "nopq 0x2(%%r9, %%rax, 1)" ASM_LE
    "nopq 0x7e(%%rax, %%rax, 1)" ASM_LE
    "mov %%rax, %0" ASM_LE
    "popq %6" ASM_LE
    "popq %5" ASM_LE
    : "=rm" (result)
    : "g" (fake_number),
      "rm" (fake_arg0),
      "rm" ((uintptr_t)real_number),
      "rm" (real_arg0),
      "rm" (real_arg1),
      "rm" (real_arg2)
    : "rax", "rcx", "rbx", "rdi", "r9", "r11", "memory");
  // clang-format on
  if (result < 0) {
    errno = -result;
    return -1;
  }
  return result;
}

[[gnu::always_inline]]
static inline long nopcall_3f_0r(
    long fake_number,
    uintptr_t fake_arg0,
    uintptr_t fake_arg1,
    uintptr_t fake_arg2,
    NopcallCode_t real_number
) {
  long result;
  // clang-format off
  asm volatile (
    "mov %1, %%rax" ASM_LE
    "mov %2, %%rdi" ASM_LE
    "mov %3, %%rsi" ASM_LE
    "mov %4, %%rdx" ASM_LE
    "mov %5, %%rbx" ASM_LE
    "nopq 0x7f(%%rax, %%rax, 1)" ASM_LE
    "syscall" ASM_LE
    "nopq 0x1(%%rbx, %%rax, 1)" ASM_LE
    "nopq 0x7e(%%rax, %%rax, 1)" ASM_LE
    "mov %%rax, %0" ASM_LE
    : "=rm" (result)
    : "g" (fake_number),
      "rm" (fake_arg0),
      "rm" (fake_arg1),
      "rm" (fake_arg2),
      "rm" ((uintptr_t)real_number)
    : "rax", "rcx", "rdx", "rbx", "rdi", "rsi", "r11", "memory");
  // clang-format on
  if (result < 0) {
    errno = -result;
    return -1;
  }
  return result;
}

[[gnu::always_inline]]
static inline long nopcall_3f_1r(
    long fake_number,
    uintptr_t fake_arg0,
    uintptr_t fake_arg1,
    uintptr_t fake_arg2,
    NopcallCode_t real_number,
    uintptr_t real_arg0
) {
  long result;
  // clang-format off
  asm volatile (
    "mov %1, %%rax" ASM_LE
    "mov %2, %%rdi" ASM_LE
    "mov %3, %%rsi" ASM_LE
    "mov %4, %%rdx" ASM_LE
    "mov %5, %%rbx" ASM_LE
    "mov %6, %%r8" ASM_LE
    "nopq 0x7f(%%rax, %%rax, 1)" ASM_LE
    "syscall" ASM_LE
    "nopq 0x2(%%r8, %%rax, 1)" ASM_LE
    "nopq 0x1(%%rbx, %%rax, 1)" ASM_LE
    "nopq 0x7e(%%rax, %%rax, 1)" ASM_LE
    "mov %%rax, %0" ASM_LE
    : "=rm" (result)
    : "g" (fake_number),
      "rm" (fake_arg0),
      "rm" (fake_arg1),
      "rm" (fake_arg2),
      "rm" ((uintptr_t)real_number),
      "rm" (real_arg0)
    : "rax", "rcx", "rdx", "rbx", "rdi", "rsi", "r8", "r11", "memory");
  // clang-format on
  if (result < 0) {
    errno = -result;
    return -1;
  }
  return result;
}

[[gnu::always_inline]]
static inline long nopcall_3f_2r(
    long fake_number,
    uintptr_t fake_arg0,
    uintptr_t fake_arg1,
    uintptr_t fake_arg2,
    NopcallCode_t real_number,
    uintptr_t real_arg0,
    uintptr_t real_arg1
) {
  long result;
  // clang-format off
  asm volatile (
    "mov %1, %%rax" ASM_LE
    "mov %2, %%rdi" ASM_LE
    "mov %3, %%rsi" ASM_LE
    "mov %4, %%rdx" ASM_LE
    "mov %5, %%rbx" ASM_LE
    "mov %6, %%r9" ASM_LE
    "mov %7, %%r8" ASM_LE
    "nopq 0x7f(%%rax, %%rax, 1)" ASM_LE
    "syscall" ASM_LE
    "nopq 0x3(%%r8, %%rax, 1)" ASM_LE
    "nopq 0x1(%%rbx, %%rax, 1)" ASM_LE
    "nopq 0x2(%%r9, %%rax, 1)" ASM_LE
    "nopq 0x7e(%%rax, %%rax, 1)" ASM_LE
    "mov %%rax, %0" ASM_LE
    : "=rm" (result)
    : "g" (fake_number),
      "rm" (fake_arg0),
      "rm" (fake_arg1),
      "rm" (fake_arg2),
      "rm" ((uintptr_t)real_number),
      "rm" (real_arg0),
      "rm" (real_arg1)
    : "rax", "rcx", "rdx", "rbx", "rdi", "rsi", "r8", "r9", "r11", "memory");
  // clang-format on
  if (result < 0) {
    errno = -result;
    return -1;
  }
  return result;
}

[[gnu::always_inline]]
static inline long nopcall_3f_3r(
    long fake_number,
    uintptr_t fake_arg0,
    uintptr_t fake_arg1,
    uintptr_t fake_arg2,
    NopcallCode_t real_number,
    uintptr_t real_arg0,
    uintptr_t real_arg1,
    uintptr_t real_arg2
) {
  long result;
  // clang-format off
  asm volatile (
    "mov %1, %%rax" ASM_LE
    "mov %2, %%rdi" ASM_LE
    "mov %3, %%rsi" ASM_LE
    "mov %4, %%rdx" ASM_LE
    "mov %5, %%rbx" ASM_LE
    "mov %6, %%r9" ASM_LE
    "pushq %7" ASM_LE
    "pushq %8" ASM_LE
    "nopq 0x7f(%%rax, %%rax, 1)" ASM_LE
    "syscall" ASM_LE
    "nopq 0x3(%%rcx, %%rax, 2)" ASM_LE
    "nopq 0x1(%%rbx, %%rax, 1)" ASM_LE
    "nopq 0x4(%%rax, %%rax, 2)" ASM_LE
    "nopq 0x2(%%r9, %%rax, 1)" ASM_LE
    "nopq 0x7e(%%rax, %%rax, 1)" ASM_LE
    "mov %%rax, %0" ASM_LE
    "popq %8" ASM_LE
    "popq %7" ASM_LE
    : "=rm" (result)
    : "g" (fake_number),
      "rm" (fake_arg0),
      "rm" (fake_arg1),
      "rm" (fake_arg2),
      "rm" ((uintptr_t)real_number),
      "rm" (real_arg0),
      "rm" (real_arg1),
      "rm" (real_arg2)
    : "rax", "rcx", "rdx", "rbx", "rdi", "rsi", "r9", "r11", "memory");
  // clang-format on
  if (result < 0) {
    errno = -result;
    return -1;
  }
  return result;
}

[[gnu::always_inline]]
static inline bool is_nopcall_marker(const NopcallMarker_t *marker) {
  return marker->prefix.fixed0 == 0b010010 && marker->opcode[0] == 0b00001111
         && marker->opcode[1] == 0b00011111 && marker->modrm.mod == 0b01
         && marker->modrm.rm == 0b100;
}

[[gnu::always_inline]]
static inline uint8_t nopcall_marker_get_idx_base(const NopcallMarker_t *marker) {
  return ((uint8_t)marker->prefix.rex_b << 3) | (uint8_t)marker->sib.base;
}

[[gnu::always_inline]]
static inline uintptr_t nopcall_get_reg_val(const struct user_regs_struct *regs, uint8_t reg_idx) {
  switch (reg_idx & 0b1111) {
    case 0b0000: return regs->orig_rax;
    case 0b0001: return regs->rcx;
    case 0b0010: return regs->rdx;
    case 0b0011: return regs->rbx;
    case 0b0100: return regs->rsp;
    case 0b0101: return regs->rbp;
    case 0b0110: return regs->rsi;
    case 0b0111: return regs->rdi;
    case 0b1000: return regs->r8;
    case 0b1001: return regs->r9;
    case 0b1010: return regs->r10;
    case 0b1011: return regs->r11;
    case 0b1100: return regs->r12;
    case 0b1101: return regs->r13;
    case 0b1110: return regs->r14;
    case 0b1111: return regs->r15;
    default: return 0;
  }
}

[[gnu::always_inline]]
static inline const char *nopcall_get_reg_name(uint8_t reg_idx) {
  switch (reg_idx & 0b1111) {
    case 0b0000: return "rax";
    case 0b0001: return "rcx";
    case 0b0010: return "rdx";
    case 0b0011: return "rbx";
    case 0b0100: return "rsp";
    case 0b0101: return "rbp";
    case 0b0110: return "rsi";
    case 0b0111: return "rdi";
    case 0b1000: return "r8";
    case 0b1001: return "r9";
    case 0b1010: return "r10";
    case 0b1011: return "r11";
    case 0b1100: return "r12";
    case 0b1101: return "r13";
    case 0b1110: return "r14";
    case 0b1111: return "r15";
    default: return "(unknown)";
  }
}

#endif /* CALLCONV_H_INCLUDED_ */
