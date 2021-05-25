#include <stdio.h>
int ga = 2;
int gb = 0;
int fun(int a) { return ~a + 1; }
int foo() __attribute__((weak));
int main(int argc, char *argv[]) {
  if (foo)
    foo();
  printf("hello\n");
  return 0;
}
int foo() {
  printf("foo\n");
  return 0;
}
