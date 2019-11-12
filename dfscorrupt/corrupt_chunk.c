#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "include/dfs.h"
#include "include/dfsck_util.h"

#define CORRUPT_BYTES   1024

void *mem, *image_mem;
struct dfs_fs *sb;

int main(int argc, char *argv[])
{
    if (argc != 3) {
        printf("Usage: corrupt_chunk <image>\n");
        exit(1);
    }

    int fp = open(argv[1], O_RDWR);
    if (fp < 0) {
        printf("Error: failed to open image.\n");
        exit(1);
    }

    struct stat st;
    if (stat(argv[1], &st) != 0) {
        printf("Error: failed to read image.\n");
        exit(1);
    }

    mem = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fp, 0);
    if (!mem) {
        printf("Error: failed to map image to memory.\n");
        exit(1);
    }
    close(fp);

    sb = (struct dfs_fs *)mem;
    image_mem = sb->mem;

    char *chunks = img_to_mem(sb->chunks);

    int chunk_index = atoi(argv[2]);
    int bytes = CORRUPT_BYTES;
    printf(":: Corrupting starting %d bytes of chunk #%d...", bytes, chunk_index);
    memset(chunks + chunk_index * sb->chunk_size, '=', bytes);   /* Corrupt 1KB. */
    printf("Done\n");

    return 0;
}
