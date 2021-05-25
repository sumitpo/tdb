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

#include "read_elf64.h"
#include "read_elf32.h"

typedef struct breakpoint64 {
  Elf64_Addr addr;
} bp64;

typedef struct breakpoint32 {
  Elf32_Addr addr;
} bp32;

int global_pid;

char *get_exe_name(int);
void sighandler(int);

#define EXE_MODE 0
#define PID_MODE 1

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
  read_elf64_info(&h, pid);

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
