#include"dfsck.h"
#include<stdio.h>
#include<stdlib.h>
#include<fcntl.h>
#include <unistd.h>
#include<sys/mman.h>
#include<sys/stat.h>
#include<string.h>

void* mem;
void* image_mem;

void* image_to_mmap(void* addr) {
    if(addr == NULL)
        return NULL;
    unsigned long int int_offset = (unsigned long int)(addr
            - image_mem) / sizeof(unsigned long int);
    return (void*)mem + int_offset*sizeof(unsigned long int);
}

int main(int argc, char *argv[]) {

	struct stat st;
	void *metachunk;
    
	unsigned long int sb_size, meta_size;
	int rd;
	void** rdAddr;

    struct dfs_dentry *dentry2corrupt;
    struct dfs_inode *inode2corrupt;

	//check if i have an image
    if (argc != 4) {
        fprintf(stderr, "Please provide a denseFS image.\n");
        exit(1);
    }
    int depth = atoi(argv[3]);
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
    struct dfs_fs *sb = (struct dfs_fs*)mem;
    image_mem = sb->mem;
    sb_size = 0x1000;

    dentry2corrupt = (struct dfs_dentry*)&sb->rootdir;
    inode2corrupt = (struct dfs_inode*)image_to_mmap(dentry2corrupt->inode);
    for(int i = 0; i < depth ; i++){
        dentry2corrupt = (struct dfs_dentry*)image_to_mmap(inode2corrupt->data.dirents.first);
        for(int j = 0; j < 127; j++){
            dentry2corrupt = (struct dfs_dentry*)image_to_mmap(dentry2corrupt->list.next);
        }
        inode2corrupt = (struct dfs_inode*)image_to_mmap(dentry2corrupt->inode);
    }


    if(!strcmp(argv[2],"dentry")){
        dentry2corrupt->inode = (void*)0xfafafafafafafafa;
    }

    if(!strcmp(argv[2],"inode")){
        inode2corrupt->data.dirents.first = (void*)0xfafafafafafafafa;
    }
    if(!strcmp(argv[2],"x")){
        dentry2corrupt->list.next = (void*)0xfafafafafafafafa;
    }

    close(fp);
    exit(0);
}
