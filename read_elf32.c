#include "read_elf32.h"

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
  disasm = disassembler(bfd_arch_i386, 0, bfd_mach_x64_32, NULL);

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

void print_raw(char *buf, int size, int width) {
  for (int i = 0; i < size; i++) {
    printf("%02x", buf[i]);
    if ((i + 1) % width == 0) {
      printf("\n");
    } else {
      printf(" ");
    }
  }
}

Elf32_Addr lookup_symbol(handle32_t *h, const char *symname) {
  int i, j;
  char *strtab;
  Elf32_Sym *symtab;
  for (i = 0; i < h->ehdr->e_shnum; i++) {
    if (h->shdr[i].sh_type == SHT_SYMTAB) {
      strtab = (char *)&h->mem[h->shdr[h->shdr[i].sh_link].sh_offset];
      symtab = (Elf32_Sym *)&h->mem[h->shdr[i].sh_offset];
      for (j = 0; j < h->shdr[i].sh_size / sizeof(Elf32_Sym); j++, symtab++) {
        if (strcmp(&strtab[symtab->st_name], symname) == 0)
          return (symtab->st_value);
      }
    }
  }
  return 0;
}

void list_dynamic(handle32_t *h, const int index) {
  Elf32_Dyn *dynamic = (Elf32_Dyn *)&h->mem[h->shdr[index].sh_offset];
  int i, num = h->shdr[index].sh_size / sizeof(Elf32_Dyn);
  for (i = 0; i < num; i++, dynamic++) {
    switch (dynamic->d_tag) {
    case DT_SYMTAB: {
      break;
    }
    case DT_STRTAB: {
      break;
    }
    case DT_STRSZ: {
      break;
    }
    case DT_HASH: {
      break;
    }
    }
  }
}

void list_symbol(handle32_t *h, const int index) {
  Elf32_Sym *symtab = (Elf32_Sym *)&h->mem[h->shdr[index].sh_offset];
  int j, num = h->shdr[index].sh_size / sizeof(Elf32_Sym);
  for (j = 0; j < num; j++, symtab++) {
    switch (symtab->st_shndx) {
    case SHN_ABS: {
      printf("ABS    %-12p", (void *)symtab->st_value);
      break;
    }
    case SHN_COMMON: {
      printf("COMMON %-12lx", symtab->st_value);
      break;
    }
    case SHN_UNDEF: {
      printf("UNDEF  %-12p", (void *)symtab->st_value);
      break;
    }
    default: {
      printf("%-6x ", symtab->st_shndx);
      printf("%-12p", (void *)symtab->st_value);
      break;
    }
    }
    switch (ELF32_ST_BIND(symtab->st_info)) {
    case STB_LOCAL: {
      printf("%-6s", "LOCAL");
      break;
    }
    case STB_GLOBAL: {
      printf("%-6s", "GLOBAL");
      break;
    }
    case STB_WEAK: {
      printf("%-6s", "WEAK");
      break;
    }
    default: {
      printf("%-6s", "");
      break;
    }
    }
    printf("\t");
    switch (ELF32_ST_TYPE(symtab->st_info)) {
    case STT_NOTYPE: {
      printf("%-6s", "NOTYPE");
      break;
    }
    case STT_OBJECT: {
      printf("%-6s", "OBJECT");
      break;
    }
    case STT_FUNC: {
      printf("%-6s", "FUNC");
      break;
    }
    case STT_SECTION: {
      printf("%-6s", "SECTION");
      break;
    }
    case STT_FILE: {
      printf("%-6s", "FILE");
      break;
    }
    }
    printf("\t");
    printf("%s\n", h->mem + h->strtab + symtab->st_name);
  }
}

void print_section_hdr(handle32_t *h) {
  printf("strtab offset %lx\n", h->strtab);
  for (int i = 0; i < h->ehdr->e_shnum; i++) {
    if (strcmp((char *)h->mem + h->shstrtab + h->shdr[i].sh_name, ".got.plt") ==
        0) {
      print_raw(h->mem + h->shdr[i].sh_offset, h->shdr[i].sh_size, 8);
    }
    if (strcmp((char *)h->mem + h->shstrtab + h->shdr[i].sh_name, ".dynamic") ==
        0) {
      list_dynamic(h, i);
    }
    if (strcmp((char *)h->mem + h->shstrtab + h->shdr[i].sh_name, ".got.plt") ==
        0) {
      char *dis =
          disassemble_raw(h->mem + h->shdr[i].sh_offset, h->shdr[i].sh_size);
      puts(dis);
      free(dis);
    }
    if (h->shdr[i].sh_type == SHT_SYMTAB) {
      list_symbol(h, i);
    }
    printf("%-20s %10lx %10lx\n", h->mem + h->shstrtab + h->shdr[i].sh_name,
           h->shdr[i].sh_offset, h->shdr[i].sh_size);
  }
}

int read_elf32_info(handle32_t *h, int pid) {
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

  h->ehdr = (Elf32_Ehdr *)h->mem;
  h->phdr = (Elf32_Phdr *)(h->mem + h->ehdr->e_phoff);
  h->shdr = (Elf32_Shdr *)(h->mem + h->ehdr->e_shoff);
  h->shstrtab = h->shdr[h->ehdr->e_shstrndx].sh_offset;

  for (int i = 0; i < h->ehdr->e_shnum; i++) {
    if (h->shdr[i].sh_type == SHT_STRTAB) {
      if (strcmp((char *)h->mem + h->shstrtab + h->shdr[i].sh_name,
                 ".strtab") == 0) {
        h->strtab = h->shdr[i].sh_offset;
      }
    }
  }

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
