CC		 = gcc
CFLAGS	 = -Wall -Werror -Wno-unused-variable -Wno-unused-function -g
LDFLAGS  =
OBJFILES = dfscorrupt.o dfsck_util.o interval_tree_util.o
TARGET   = dfscorrupt

all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)
	rm $(OBJFILES)

corrupt_chunk: corrupt_chunk.c dfsck_util.c interval_tree_util.c
	$(CC) $(CFLAGS) -o corrupt_chunk corrupt_chunk.c dfsck_util.c interval_tree_util.c

clean:
	rm -f $(OBJFILES) $(TARGET) *~
