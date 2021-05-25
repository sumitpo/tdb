#define _GNU_SOURCE /* asprintf, vasprintf */
#define PACKAGE 1
#define PACKAGE_VERSION 1

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <dis-asm.h>

typedef struct handle32 {
  Elf32_Ehdr *ehdr;
  Elf32_Phdr *phdr;
  Elf32_Shdr *shdr;
  Elf32_Off strtab;
  Elf32_Off shstrtab;
  uint8_t *mem;
  char *symname;
  Elf32_Addr symaddr;
  struct user_regs_struct pt_reg;
  char *exec;
} handle32_t;

typedef struct {
  char *insn_buffer;
  int reenter;
} stream_state;

static int dis_fprintf(void *stream, const char *fmt, ...);

char *disassemble_raw(uint8_t *input_buffer, size_t input_buffer_size);

void print_raw(char *buf, int size, int width); 

Elf32_Addr lookup_symbol(handle32_t *h, const char *symname);

void list_dynamic(handle32_t *h, const int index);

void list_symbol(handle32_t *h, const int index);

void print_section_hdr(handle32_t *h);

int read_elf32_info(handle32_t *h, int pid);
