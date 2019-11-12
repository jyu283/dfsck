CC = gcc
CFLAGS = -Wall -Wno-unused-variable -Wno-unused-function -Werror -g -std=c11
LDFLAGS = 
OBJFILES = dfsck.o \
		   stack.o \
		   list.o \
		   dfs_allocation.o \
		   dfsck_util.o \
		   interval_tree_util.o \
		   rbtree.o
TARGET = dfsck

all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)

clean:
	rm -f $(OBJFILES) $(TARGET) *~
