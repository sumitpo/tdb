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

typedef struct handle64 {
  Elf64_Ehdr *ehdr;
  Elf64_Phdr *phdr;
  Elf64_Shdr *shdr;
  Elf64_Off strtab;
  uint8_t *mem;
  char *symname;
  Elf64_Addr symaddr;
  struct user_regs_struct pt_reg;
  char *exec;
} handle64_t;

typedef struct handle32 {
  Elf32_Ehdr *ehdr;
  Elf32_Phdr *phdr;
  Elf32_Shdr *shdr;
  Elf32_Off strtab;
  uint8_t *mem;
  char *symname;
  Elf32_Addr symaddr;
  struct user_regs_struct pt_reg;
  char *exec;
} handle32_t;

typedef struct breakpoint {
  Elf64_Addr addr;
} bp;

typedef struct {
  char *insn_buffer;
  int reenter;
} stream_state;

int global_pid;

Elf64_Addr lookup_symbol(handle64_t *, const char *);
char *get_exe_name(int);
void sighandler(int);

#define EXE_MODE 0
#define PID_MODE 1

static int dis_fprintf(void *stream, const char *fmt, ...) {
  stream_state *ss = (stream_state *)stream;

  va_list arg;
  va_start(arg, fmt);
  if (!ss->reenter) {
    vasprintf(&ss->insn_buffer, fmt, arg);
    ss->reenter = 1;
  } else {
    char *tmp;
    vasprintf(&tmp, fmt, arg);

    char *tmp2;
    asprintf(&tmp2, "%s%s", ss->insn_buffer, tmp);
    free(ss->insn_buffer);
    free(tmp);
    ss->insn_buffer = tmp2;
  }
  va_end(arg);

  return 0;
}

char *disassemble_raw(uint8_t *input_buffer, size_t input_buffer_size) {
  char *disassembled = NULL;
  stream_state ss = {};

  disassemble_info disasm_info = {};
  init_disassemble_info(&disasm_info, &ss, dis_fprintf);
  disasm_info.arch = bfd_arch_i386;
  disasm_info.mach = bfd_mach_x86_64;
  disasm_info.read_memory_func = buffer_read_memory;
  disasm_info.buffer = input_buffer;
  disasm_info.buffer_vma = 0;
  disasm_info.buffer_length = input_buffer_size;
  disassemble_init_for_target(&disasm_info);

  disassembler_ftype disasm;
  disasm = disassembler(bfd_arch_i386, 0, bfd_mach_x86_64, NULL);

  size_t pc = 0;
  while (pc < input_buffer_size) {
    size_t insn_size = disasm(pc, &disasm_info);
    pc += insn_size;

    if (disassembled == NULL) {
      asprintf(&disassembled, "%s", ss.insn_buffer);
    } else {
      char *tmp;
      asprintf(&tmp, "%s\n%s", disassembled, ss.insn_buffer);
      free(disassembled);
      disassembled = tmp;
    }

    /* Reset the stream state after each instruction decode.
     */
    free(ss.insn_buffer);
    ss.reenter = 0;
  }

  return disassembled;
}

void parse_args(int argc, char **argv, handle64_t *h, int *mode, int *pid) {
  int c;
  while ((c = getopt(argc, argv, "p:e:f:")) != -1) {
    switch (c) {
    case 'p':
      *pid = atoi(optarg);
      h->exec = get_exe_name(*pid);
      if (h->exec == NULL) {
        printf("Unable to retrieve executable path for pid: %d\n", *pid);
        exit(-1);
      }
      *mode = PID_MODE;
      break;
    case 'e':
      if ((h->exec = strdup(optarg)) == NULL) {
        perror("strdup");
        exit(-1);
      }
      mode = EXE_MODE;
      break;
    case 'f':
      if ((h->symname = strdup(optarg)) == NULL) {
        perror("strdup");
        exit(-1);
      }
      break;
    default:
      printf("Unknown option\n");
      break;
    }
  }
  if (h->symname == NULL) {
    printf("Specifying a function name with -f option is required\n");
    exit(-1);
  }
}

void print_section_hdr(handle64_t *h) {
  printf("strtab offset %lx\n", h->strtab);
  for (int i = 0; i < h->ehdr->e_shnum; i++) {
    if (strcmp((char *)h->mem + h->strtab + h->shdr[i].sh_name, ".text") == 0) {
      char * dis = disassemble_raw(h->mem+h->shdr[i].sh_offset, h->shdr[i].sh_size);
      puts(dis);
      free(dis);
    }
    printf("%-20s| %10lx| %10lx\n", h->mem + h->strtab + h->shdr[i].sh_name,
           h->shdr[i].sh_offset, h->shdr[i].sh_size);
  }
}

int read_elf_info(handle64_t *h, int pid) {
  int fd;
  struct stat st;
  if ((fd = open(h->exec, O_RDONLY)) < 0) {
    perror("open");
    exit(-1);
  }

  if (fstat(fd, &st) < 0) {
    perror("fstat");
    exit(-1);
  }

  h->mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (h->mem == MAP_FAILED) {
    perror("mmap");
    exit(-1);
  }

  h->ehdr = (Elf64_Ehdr *)h->mem;
  h->phdr = (Elf64_Phdr *)(h->mem + h->ehdr->e_phoff);
  h->shdr = (Elf64_Shdr *)(h->mem + h->ehdr->e_shoff);
  h->strtab = h->shdr[h->ehdr->e_shstrndx].sh_offset;

  if (h->mem[0] != 0x7f && !strcmp((char *)&h->mem[1], "ELF")) {
    printf("%s is not an ELF file\n", h->exec);
    exit(-1);
  }

  if (h->ehdr->e_type != ET_EXEC) {
    printf("%s is not an ELF executable\n", h->exec);
    exit(-1);
  }

  if (h->ehdr->e_shstrndx == 0 || h->ehdr->e_shoff == 0 ||
      h->ehdr->e_shnum == 0) {
    printf("Section header table not found\n");
    exit(-1);
  }
  print_section_hdr(h);

  if ((h->symaddr = lookup_symbol(h, h->symname)) == 0) {
    printf("Unable to find symbol: %s not found in executable\n", h->symname);
    exit(-1);
  }

  close(fd);
  return 0;
}
int get_all_regs(handle64_t *h, int pid) {
  if (ptrace(PTRACE_GETREGS, pid, NULL, &h->pt_reg) < 0) {
    perror("PTRACE_GETREGS");
    exit(-1);
  }

  return 0;
}
int print_regs(handle64_t *h) {
  /*
  printf("\nExecutable %s (pid: %d) has hit breakpoint 0x%lx\n",
         h->exec, pid, h->symaddr);
  */
  printf("sizeof %lu\n", sizeof(h->pt_reg));

  printf("%%rcx: 0x%016llx %%rdx: 0x%16llx %%rbx: 0x%16llx\n"
         "%%rax: 0x%016llx %%rdi: 0x%16llx %%rsi: 0x%16llx\n"
         "%%r8 : 0x%016llx %%r9 : 0x%16llx %%r10: 0x%16llx\n"
         "%%r11: 0x%016llx %%r12: 0x%16llx %%r13: 0x%16llx\n"
         "%%r14: 0x%016llx %%r15: 0x%16llx %%rsp: 0x%16llx\n",
         h->pt_reg.rcx, h->pt_reg.rdx, h->pt_reg.rbx, h->pt_reg.rax,
         h->pt_reg.rdi, h->pt_reg.rsi, h->pt_reg.r8, h->pt_reg.r9,
         h->pt_reg.r10, h->pt_reg.r11, h->pt_reg.r12, h->pt_reg.r13,
         h->pt_reg.r14, h->pt_reg.r15, h->pt_reg.rsp);
  return 0;
}

int main(int argc, char **argv, char **envp) {
  int fd, mode = 0;
  handle64_t h;
  struct stat st;
  long trap, orig;
  int status, pid;
  char *args[2];

  if (argc < 3) {
    printf("Usage: %s [-ep <exe>/<pid>] [-f <fname>]\n", argv[0]);
    exit(0);
  }

  memset(&h, 0, sizeof(handle64_t));
  parse_args(argc, argv, &h, &pid, &mode);

  if (mode == EXE_MODE) {
    args[0] = h.exec;
    args[1] = NULL;
  }

  signal(SIGINT, sighandler);

  /********************************************/
  read_elf_info(&h, pid);

  if (mode == EXE_MODE) {
    if ((pid = fork()) < 0) {
      perror("fork");
      exit(-1);
    }

    if (pid == 0) {
      if (ptrace(PTRACE_TRACEME, pid, NULL, NULL) < 0) {
        perror("PTRACE_TRACEME");
        exit(-1);
      }
      execve(h.exec, args, envp);
      exit(0);
    }
  } else {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
      perror("PTRACE_ATTACH");
      exit(-1);
    }
  }
  wait(&status);

  global_pid = pid;

  printf("Beginning analysis of pid: %d at %lx\n", pid, h.symaddr);

  if ((orig = ptrace(PTRACE_PEEKTEXT, pid, h.symaddr, NULL)) < 0) {
    perror("PTRACE_PEEKTEXT");
    exit(-1);
  }

  trap = (orig & ~0xff) | 0xcc;

  if (ptrace(PTRACE_POKETEXT, pid, h.symaddr, trap) < 0) {
    perror("PTRACE_POKETEXT");
    exit(-1);
  }

trace:
  if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
    perror("PTRACE_CONT");
    exit(-1);
  }

  wait(&status);

  if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
    get_all_regs(&h, pid);
    print_regs(&h);

    printf("\nPlease hit any key to continue: ");
    getchar();

    if (ptrace(PTRACE_POKETEXT, pid, h.symaddr, orig) < 0) {
      perror("PTRACE_POKETEXT");
      exit(-1);
    }

    h.pt_reg.rip = h.pt_reg.rip - 1;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &h.pt_reg) < 0) {
      perror("PTRACE_SETREGS");
      exit(-1);
    }

    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) {
      perror("PTRACE_SINGLESTEP");
      exit(-1);
    }

    wait(NULL);

    if (ptrace(PTRACE_POKETEXT, pid, h.symaddr, trap) < 0) {
      perror("PTRACE_POKETEXT");
      exit(-1);
    }

    goto trace;
  }

  if (WIFEXITED(status))
    printf("Completed tracing pid: %d\n", pid);

  exit(0);
}

Elf64_Addr lookup_symbol(handle64_t *h, const char *symname) {
  int i, j;
  char *strtab;
  Elf64_Sym *symtab;
  for (i = 0; i < h->ehdr->e_shnum; i++) {
    if (h->shdr[i].sh_type == SHT_SYMTAB) {
      strtab = (char *)&h->mem[h->shdr[h->shdr[i].sh_link].sh_offset];
      symtab = (Elf64_Sym *)&h->mem[h->shdr[i].sh_offset];
      for (j = 0; j < h->shdr[i].sh_size / sizeof(Elf64_Sym); j++, symtab++) {
        if (strcmp(&strtab[symtab->st_name], symname) == 0)
          return (symtab->st_value);
      }
    }
  }
  return 0;
}

/*
 * get exe name from /proc/{pid}/cmdline
 */
char *get_exe_name(int pid) {
  char cmdline[255], path[512], *p;
  int fd;

  snprintf(cmdline, 255, "/proc/%d/cmdline", pid);

  if ((fd = open(cmdline, O_RDONLY)) < 0) {
    perror("open");
    exit(1);
  }

  if (read(fd, path, 512) < 0) {
    perror("read");
    exit(1);
  }

  if ((p = strdup(path)) == NULL) {
    perror("strdup");
    exit(1);
  }

  return p;
}

void sighandler(int sig) {
  printf("Caught SIGINT: Detaching from %d\n", global_pid);

  if (ptrace(PTRACE_DETACH, global_pid, NULL, NULL) < 0 && errno) {
    perror("PTRACE_DETACH");
    exit(-1);
  }
  exit(0);
}
