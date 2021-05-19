CC = gcc
LDFLAGS = -lopcodes
TARGET = tdb hello


all:$(TARGET)
tdb:tdb.o
	$(CC) -o $@ $< $(LDFLAGS)
hello:hello.o
	$(CC) -no-pie -o $@ $<
clean:
	-rm $(TARGET) *.o
run:
	./tdb -e hello -f main
