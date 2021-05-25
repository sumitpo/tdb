CC = gcc
LDFLAGS = -lopcodes
TARGET = tdb hello libelf64.so libelf32.so

all:$(TARGET)
tdb:tdb.o libelf64.so libelf32.so
	$(CC) -o $@ $< -L. -lelf64 
	LD_LIBRARY_PATH=$LD_LIBRARY_PATH:.
	export $LD_LIBRARY_PATH
libelf64.so:read_elf64.o
	$(CC) -fpic -shared -o $@ $< $(LDFLAGS)
libelf32.so:read_elf32.o
	$(CC) -fpic -shared -o $@ $< $(LDFLAGS)
read_elf64.o:read_elf64.c
read_elf32.o:read_elf32.c
hello:hello.o
	$(CC) -no-pie -o $@ $<
clean:
	-rm $(TARGET) *.o
run:
	./tdb -e hello -f main
