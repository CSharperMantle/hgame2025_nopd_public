#ifndef PTRACE_HELPER_H_INCLUDED_
#define PTRACE_HELPER_H_INCLUDED_

#include <stdint.h>
#include <unistd.h>

ssize_t ptrace_peektext_memcpy(pid_t pid, void *dest, uintptr_t src, size_t n);
ssize_t ptrace_peekdata_memcpy(pid_t pid, void *dest, uintptr_t src, size_t n);
ssize_t ptrace_pokedata_memcpy(pid_t pid, uintptr_t dest, void *src, size_t n);

#endif /* PTRACE_HELPER_H_INCLUDED_ */