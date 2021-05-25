#define _GNU_SOURCE /* asprintf, vasprintf */
#define PACKAGE 1
#define PACKAGE_VERSION 1

#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>

#include <dis-asm.h>

typedef struct {
  char *insn_buffer;
  int reenter;
} stream_state;

static int dis_fprintf(void *stream, const char *fmt, ...);

char *disassemble_raw(uint8_t *input_buffer, size_t input_buffer_size, int bit);
