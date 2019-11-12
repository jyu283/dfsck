#include"dfsck.h"
#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>
#include <unistd.h>
#include<sys/mman.h>
#include<sys/stat.h>
#include<string.h>

int main(int argc, char *argv[]) {

	struct stat st;
	void *mem;
	void *metachunk;
	unsigned long int sb_size, meta_size;
	int rd;
	void** rdAddr;
	    //check if i have an image
    if (argc != 5) {
        fprintf(stderr, "Please provide a denseFS image.\n");
        exit(1);
    }
    //open the FS image
    int fp = open(argv[1], O_RDWR);
    if (fp < 0) {
        fprintf(stderr, "DenseFS image can't be opened.\n");
        exit(1);
    }
    //get some simple image file details

    if (stat(argv[1], &st) != 0) {
        fprintf(stderr, "DneseFS image file details unaccessible.\n");
        exit(1);
    }
    //mmap the entire image into memory
    mem = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fp, 0);
    if (mem == NULL) {
        printf("Couldn't mmap the DenseFS image.\n");
        exit(1);
    }

    sb_size = 0x1000;
    meta_size = st.st_size >> 4;
    metachunk = (void *)(mem + sb_size);
    srand(atoi(argv[3]));

    int numCorruptions = atoi(argv[2]);
    for(int i = 0; i < numCorruptions; i++){
        rd = rand() % meta_size;
        printf("rand number: %i\n", rd);
        rdAddr = (void **)(metachunk + rd);
        for(int i = 0; i < atoi(argv[4])/8; i++){
            *(rdAddr + (i*8)) = (void *)0xfafafafafafafafa;
        }
    }

    close(fp);
    exit(0);
}