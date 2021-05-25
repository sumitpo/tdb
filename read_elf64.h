#define _GNU_SOURCE /* asprintf, vasprintf */
#define PACKAGE 1
#define PACKAGE_VERSION 1

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <dis-asm.h>

typedef struct handle64 {
  Elf64_Ehdr *ehdr;
  Elf64_Phdr *phdr;
  Elf64_Shdr *shdr;
  Elf64_Off strtab;
  Elf64_Off shstrtab;
  uint8_t *mem;
  char *symname;
  Elf64_Addr symaddr;
  struct user_regs_struct pt_reg;
  char *exec;
} handle64_t;

typedef struct {
  char *insn_buffer;
  int reenter;
} stream_state;

Elf64_Addr lookup_symbol(handle64_t *, const char *);

static int dis_fprintf(void *stream, const char *fmt, ...);

static char *disassemble_raw(uint8_t *input_buffer, size_t input_buffer_size);

void print_raw(char *buf, int size, int width);

static void list_dynamic(handle64_t *h, const int index);

static void list_symbol(handle64_t *h, const int index);

static void print_section_hdr(handle64_t *h);

int read_elf64_info(handle64_t *h, int pid) __attribute__ ((visibility("default")));
