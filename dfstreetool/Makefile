CC = gcc
CFLAGS = -Wall -Wno-unused-variable -Wno-unused-function -Werror -g
LDFLAGS = 
OBJFILES = dfstree.o dfsck_util.o
TARGET = dfstree

all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)
	rm $(OBJFILES)

clean:
	rm -f $(OBJFILES) $(TARGET) *~
