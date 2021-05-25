#include "disasm.h"

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

char *disassemble_raw(uint8_t *input_buffer, size_t input_buffer_size, int bit) {
  char *disassembled = NULL;
  stream_state ss = {};

  disassemble_info disasm_info = {};
  init_disassemble_info(&disasm_info, &ss, dis_fprintf);
  disasm_info.arch = bfd_arch_i386;
  if(bit==64)
    disasm_info.mach = bfd_mach_x86_64;
  else
    disasm_info.mach = bfd_mach_x64_32;
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
