#include "ptrace_helper.h"
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

static ssize_t ptrace_peekany_memcpy(int cmd, pid_t pid, void *dest, uintptr_t src, size_t n) {
  size_t i;
  size_t bytes_read = 0;
  for (i = 0; i < n - n % sizeof(long); i += sizeof(long)) {
    const long word = ptrace(cmd, pid, src + i, NULL);
    if (errno != 0) {
      return -errno;
    }
    memcpy(dest + i, &word, sizeof(long));
    bytes_read += sizeof(long);
  }
  const size_t remainder = n % sizeof(long);
  if (remainder > 0) {
    const long word = ptrace(cmd, pid, src + i, NULL);
    if (errno != 0) {
      return -errno;
    }
    memcpy(dest + i, &word, remainder);
    bytes_read += remainder;
  }
  return bytes_read;
}

ssize_t ptrace_peektext_memcpy(pid_t pid, void *dest, uintptr_t src, size_t n) {
  return ptrace_peekany_memcpy(PTRACE_PEEKTEXT, pid, dest, src, n);
}

ssize_t ptrace_peekdata_memcpy(pid_t pid, void *dest, uintptr_t src, size_t n) {
  return ptrace_peekany_memcpy(PTRACE_PEEKDATA, pid, dest, src, n);
}

ssize_t ptrace_pokedata_memcpy(pid_t pid, uintptr_t dest, void *src, size_t n) {
  const size_t n_aligned = n + (sizeof(long) - n % sizeof(long));
  uint8_t *const buf = malloc(n_aligned);
  if (buf == NULL) {
    return -ENOMEM;
  }
  ptrace_peekdata_memcpy(pid, buf, dest, n_aligned);
  memcpy(buf, src, n);
  for (size_t i = 0; i < n_aligned; i += sizeof(long)) {
    const long word = *(long *)(buf + i);
    ptrace(PTRACE_POKEDATA, pid, dest + i, word);
    if (errno != 0) {
      free(buf);
      return -errno;
    }
  }
  free(buf);
  return n;
}
