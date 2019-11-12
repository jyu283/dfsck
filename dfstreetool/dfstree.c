#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>

#include "include/dfs.h"
#include "include/dfsck.h"
#include "include/dfsck_util.h"

void *mem, *image_mem;
struct dfs_fs *sb;

static int file_count = 0, dir_count = 0;

static int indent_level = 0;
static int verbose = 0;

static inline unsigned long DB_get_off(void *addr)
{
    return (unsigned long)(mem_to_img(addr) - image_mem);
}

void print_indent()
{
    if (indent_level == 0)
        return;
    for (int i = 1; i < indent_level; i++) {
        printf("│   ");
    }
    printf("├── ");
}

void print_file(struct dfs_dentry *dentry)
{
    file_count++;
    print_indent();
    if (verbose) {
        struct dfs_inode *inode = map_inode(dentry->inode);
        printf("%s (inode: %lx, lms: %lx)\n", dentry->name, 
                        DB_get_off(inode), inode->__lock_metaidx_size);
    } else 
        printf("%s\n", dentry->name);
}

void print_dot_dents(struct dfs_inode *dir)
{
    struct dfs_inode *parent = map_inode(dir->extra->parent);

    print_indent();
    printf(". (%lx)\n", DB_get_off(dir));
    print_indent();
    printf(".. (%lx)\n", DB_get_off(parent));

    // struct dfs_dentry *dent_self, *dent_parent;
    // struct dfs_inode *self, *parent;
    // dent_self = &(dir->dot_dents[DENT_SELF]);
    // dent_parent = &(dir->dot_dents[DENT_PARENT]);
    // self = map_inode(dent_self->inode);
    // parent = map_inode(dent_parent->inode);
    // print_indent();
    // printf(". (%lx)\n", DB_get_off(self));
    // print_indent();
    // printf(".. (%lx)\n", DB_get_off(parent));
}

void print_dir(struct dfs_dentry *dentry)
{
    dir_count++;
    print_indent();
    if (dentry == &sb->rootdir) {
        if (verbose)
            printf(BLU "/ (inode: %lx)\n" RESET, DB_get_off(map_inode(sb->rootdir.inode)));
        else 
            printf(BLU "/\n" RESET);
    } else {
        if (verbose) {
            printf(BLU "%s (inode: %lx)\n" RESET, dentry->name, 
                                            DB_get_off(map_inode(dentry->inode)));
        } else
            printf(BLU "%s\n" RESET, dentry->name);
    }

    indent_level++;
    struct dfs_inode *dir_inode = map_inode(dentry->inode);
    if (verbose)
        print_dot_dents(dir_inode);

    struct dfs_dentry *curr_dentry = img_to_mem(dir_inode->data.dirents.next);
    
    while (curr_dentry != NULL) {
        if (isreg(map_inode(curr_dentry->inode))) {
            print_file(curr_dentry);
        } else if (isdir(map_inode(curr_dentry->inode))) {
            print_dir(curr_dentry);
        } else {
            print_indent();
            printf(RED "%s (UNKNOWN TYPE)\n" RESET, dentry->name);
        }
        curr_dentry = img_to_mem(curr_dentry->list.next);
    }
    indent_level--;
}

int main(int argc, char *argv[])
{
    if (argc != 2 && argc != 3) {
        printf("Usage: dfstree [-v|--verbose] image\n");
        exit(0);
    }

    int verbose_flag_idx = -1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
            verbose_flag_idx = i;
            break;
        }
    }

    // This is some stupid code. Determine where the -v flag is and
    // where the image path is in the command-line arguments.
    int file_name_idx = 1;
    if (verbose_flag_idx == 1)
        file_name_idx = 2;
    int fp = open(argv[file_name_idx], O_RDWR);
    if (fp < 0) {
        printf("Error: failed to open image.\n");
        exit(1);
    }

    struct stat st;
    if (stat(argv[file_name_idx], &st) != 0) {
        printf("Error: failed to read image.\n");
        exit(1);
    }

    mem = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fp, 0);
    if (!mem) {
        printf("Error: failed to map image to memory.\n");
        exit(1);
    }
    sb = (struct dfs_fs *)mem;
    image_mem = sb->mem;
    
    struct dfs_dentry *root_dir = &sb->rootdir;
    print_dir(root_dir);

    if (verbose) {
        printf("Total file count:      %d.\n", file_count);
        printf("Total directory count: %d.\n", dir_count);
    }

    exit(0);
}
