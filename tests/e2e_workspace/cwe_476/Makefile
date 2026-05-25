CC      = clang
CFLAGS  ?= -O1 -g
TARGET  = target

all: $(TARGET) target.o

$(TARGET): target.c
	$(CC) $(CFLAGS) target.c -o $(TARGET)

target.o: target.c
	$(CC) $(CFLAGS) -c target.c -o target.o

clean:
	rm -f $(TARGET) target.o

cdb:
	bear -- $(MAKE) all
