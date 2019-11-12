/**
 * This is a program to corrupt certain targets in a DenseFS file system image.
 * (e.g. prev pointers, data pointers) Used for testing the recoverability of DenseFS.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>

#include "include/dfs.h"
#include "include/dfsck_util.h"
#include "include/interval_tree_util.h"
// #include "include/dfsck.h"

// corrupted pointers will show up in hexdump as a row of '=' signs
// What genius design.
#define CORRUPT_VAL     0x3d3d3d3d3d3d3d3d  

void *mem, *image_mem;
struct dfs_fs *sb;

static struct dfs_inode **files, **dirs;
static struct dfs_dentry **dentries;
static struct dfs_datachunk **datachunks;
static size_t files_size = 10, dirs_size = 10, dentries_size = 10, datachunks_size = 10;
static int file_cnt = 0, dir_cnt = 0, dentries_cnt = 0, datachunk_cnt = 0;
static int dentries_traversed = 0;

// values are set to -1 when flag is not set. Otherwise, value between 0 and 1000
static int dentry_corrupt_rate = -1, dir_corrupt_rate = -1, file_corrupt_rate = -1,
           datachunk_corrupt_rate = -1, next_corrupt_rate = -1, data_corrupt_rate = -1,
           interval_corrupt_rate = -1, dc_full_corrupt_rate = -1, head_corrupt_rate = -1,
           bitmap_corrupt_rate = -1;

static inline int rng(int max)
{
    int num = rand();
    return num % (max + 1);
}

void insert_dentry(struct dfs_dentry *dentry)
{
    // printf("  - Inserting dentry: %s (parent = %p)\n", dentry->name, dentry->parent);
    dentries = (struct dfs_dentry **) check_capacity(dentries, 
                            &dentries_size, dentries_cnt, sizeof(struct dfs_dentry **));
    dentries[dentries_cnt] = dentry;
    dentries_cnt++;
}

void insert_datachunk(struct  dfs_datachunk *dc)
{
    datachunks = (struct dfs_datachunk **)
                 check_capacity(datachunks, &datachunks_size, datachunk_cnt, 
                            sizeof(struct dfs_datachunk **));
    datachunks[datachunk_cnt] = dc;
    datachunk_cnt++;
}

void traverse_datachunks(struct dfs_datachunk *dc)
{
    if (dc == NULL)
        return;
    dc = map_datachunk(dc);
    traverse_datachunks((struct dfs_datachunk *)dc->it.rb.rb_left);
    insert_datachunk(dc);
    traverse_datachunks((struct dfs_datachunk *)dc->it.rb.rb_right);
}

void insert_file_inode(struct dfs_inode *inode)
{
    files = (struct dfs_inode **)
            check_capacity(files, &files_size, file_cnt, sizeof(struct dfs_inode **));
    files[file_cnt] = inode;
    file_cnt++;

    struct dfs_datachunk *dc = (struct dfs_datachunk *)inode->data.chunks.rb_node;
    traverse_datachunks(dc);
}

void insert_dir_inode(struct dfs_inode *inode) 
{
    dirs = (struct dfs_inode **)
           check_capacity(dirs, &dirs_size, dir_cnt, sizeof(struct dfs_inode **));
    dirs[dir_cnt] = inode;

    // traverse all dentries
    struct dfs_dentry *curr_dentry = get_first_dentry(inode); 
    while (curr_dentry != NULL) {
        insert_dentry(curr_dentry);
        curr_dentry = map_dentry((struct dfs_dentry *)curr_dentry->list.next);
    }
    dir_cnt++;
}

void load_metadata()
{
    struct dfs_dentry *root_dentry = &sb->rootdir;
    dentries[0] = root_dentry;
    dentries_cnt++;
    dentries_traversed++;
    insert_dir_inode(map_inode(root_dentry->inode));

    struct dfs_inode *curr_inode;
    while (dentries_traversed < dentries_cnt) {
        curr_inode = map_inode(dentries[dentries_traversed]->inode);
        if (isdir(curr_inode)) {
            insert_dir_inode(curr_inode);
        } else {
            insert_file_inode(curr_inode);
        }
        dentries_traversed++;
    }
    printf("Finished loading all metadata.\n");
}

/*
 * NOTE: This is only corrupting a FIXED section of the bitmap at the moment.
 * Design idea: corrupt the "ints" field in each bitmap level.
 */
void corrupt_bitmap()
{
    char *bitmap_start = (char *)sb->chunk_bitmaps;
    bitmap_start += 4;
    memset(bitmap_start, 0xf, 1); 

    bitmap_start = (char *)&sb->chunk_bitmaps[DFS_META_FREE_BITMAP];
    bitmap_start += 1;
    memset(bitmap_start, 0xf, 1);
    printf("Bitmaps corrupted.\n");
}

void corrupt_metadata()
{
    printf("\nBeginning metadata corruption... \n");
    int files_corrupted = 0, dirs_corrupted = 0, dentries_corrupted = 0, dc_corrupted = 0,
        next_corrupted = 0, data_corrupted = 0, intervals_corrupted = 0, full_dc_corrupted = 0,
        heads_corrupted = 0;
    int rand; 

    if (file_corrupt_rate > 0) {
        srand(time(NULL));
        while (files_corrupted == 0) { 
            for (int i = 0; i < file_cnt; i++) {
                rand = rng(1000); 
                if (rand <= file_corrupt_rate) {
                    // printf(RED "  [!] Corrupting file %p!\n" RESET, mem_to_img(files[i]));
                    files[i]->data.chunks.rb_node = (void *)CORRUPT_VAL;
                    files_corrupted++;
                }
            }
        }
        // printf("File(s) corrupted.\n");
    }

    if (dir_corrupt_rate > 0) {
        srand(time(NULL));
        while (dirs_corrupted == 0) {
            for (int i = 0; i < dir_cnt; i++) {
                rand = rng(1000);
                if (rand <= dir_corrupt_rate) {
                    // printf(RED "  [!] Corrupting directory %p!\n" RESET, mem_to_img(dirs[i]));
                    dirs[i]->data.dirents.next = (void *)CORRUPT_VAL;
                    dirs_corrupted++;
                }
            }
        }
        // printf("Director(ies) corrupted.\n");
    }
    
    if (dentry_corrupt_rate > 0) {
        srand(time(NULL));
        while (dentries_corrupted == 0) {
            for (int i = 1; i < dentries_cnt; i++) {
                rand = rng(1000);
                if (rand <= dentry_corrupt_rate) {
                    // if (i == 0) {
                    //     printf(RED "  [!] Corrupting root dentry!\n" RESET);
                    // } else {
                    //     printf(RED "  [!] Corrupting dentry: %s!\n" RESET, dentries[i]->name);
                    // }
                    dentries[i]->inode = (void *)CORRUPT_VAL;
                    dentries_corrupted++;
                }
            }
        }
        // printf("Dentr(ies) corrupted.\n");
    }

    if (next_corrupt_rate > 0) {
        srand(time(NULL));
        while (next_corrupted == 0) {
            for (int i = 0; i < dentries_cnt; i++) {
                rand = rng(1000);
                if (rand <= next_corrupt_rate) {
                    // printf(RED "  [!] Corrupting next pointer of dentry: %s\n" RESET,
                    //                                                         dentries[i]->name);
                    dentries[i]->list.next = (void *)CORRUPT_VAL;
                    next_corrupted++;
                }
            }
        }
        // printf("Next pointers corrupted.\n");
    } 

    if (datachunk_corrupt_rate > 0) {
        srand(time(NULL));
        while (dc_corrupted == 0) {
            for (int i = 0; i < datachunk_cnt; i++) {
                rand = rng(1000);
                if (rand <= datachunk_corrupt_rate) {
                    int rand_lr = random() % 2;
                    if (rand_lr) {
                        // printf(RED "  [!] Corrupting left child of datachunk %p\n" RESET,
                        //                                            mem_to_img(datachunks[i]));
                        datachunks[i]->it.rb.rb_left = (void *)CORRUPT_VAL;
                    } else {
                        // printf(RED "  [!] Corrupting right child of datachunk %p\n" RESET,
                        //                                            mem_to_img(datachunks[i]));
                        datachunks[i]->it.rb.rb_right = (void *)CORRUPT_VAL;
                    }
                    dc_corrupted++;
                }
            }
        }
        // printf("Datachunk(s) corrupted.\n");
    }

    if (data_corrupt_rate > 0) {
        srand(time(NULL));
        while (data_corrupted == 0) {
            for (int i = 0; i < datachunk_cnt; i++) {
                rand = rng(1000);
                if (rand <= data_corrupt_rate) {
                    // printf(RED "  [!] Corrupting data pointer of datachunk: %p (orig: %lx)\n" RESET,
                    //                     mem_to_img(datachunks[i]), datachunks[i]->data_initialized);
                    datachunks[i]->data_initialized = CORRUPT_VAL;
                    data_corrupted++;
                    break;
                }
            }
        }
        // printf("Data pointer(s) corrupted.\n");
    }

    if (interval_corrupt_rate > 0) {
        srand(time(NULL));
        while (intervals_corrupted == 0) {
            for (int i = 0; i < datachunk_cnt; i++) {
                rand = rng(1000);
                if (rand <= interval_corrupt_rate) {
                    struct dfs_datachunk *dc = datachunks[i];
                    // printf(RED "  [!] Corrupting intervals of datachunk %p (orig: [%lx, %lx])\n" RESET,
                    //                     mem_to_img(dc), dc->it.start, dc->it.last);
                    dc->it.start = CORRUPT_VAL;
                    dc->it.last = CORRUPT_VAL;
                    intervals_corrupted++;
                }
            }
        }
        // printf("Data interval(s) corrupted.\n");
    }

    // if (dc_full_corrupt_rate > 0) {
    //     struct dfs_datachunk *dc;
    //     srand(time(NULL));
    //     while (full_dc_corrupted != 1) {
    //         for (int i = 0; i < datachunk_cnt; i++) {
    //             dc = datachunks[i];
    //             struct dfs_inode *file = map_inode(dc->parent);
    //             if (get_node_count(file) > 10 || get_node_count(file) < 6)
    //                 continue;
    //             rand = rng(1000);
    //             if (rand <= dc_full_corrupt_rate) {
    //                 memset(dc, '!', sizeof(struct dfs_datachunk));
    //                 full_dc_corrupted++;
    //                 break;
    //             }
    //         }
    //     }
    // }
    if (dc_full_corrupt_rate > 0) {
        struct dfs_datachunk *dc;
        srand(time(NULL));
        while (full_dc_corrupted == 0) {
            for (int i = 0; i < datachunk_cnt; i++) {
                rand = rng(1000);
                if (rand <= dc_full_corrupt_rate) {
                    dc = datachunks[i];
                    memset(dc, '=', sizeof(struct dfs_datachunk));
                    full_dc_corrupted++;
                }
            }
        }
        // printf("Director(ies) corrupted.\n");
    }

    int used_chunks = 0;
    if (head_corrupt_rate > 0) {
        struct lazy_list_head *heads = img_to_mem(sb->heads);
        srand(time(NULL));
        while (heads_corrupted == 0) {
            for (int i = 0; i < DFS_META_NUM_CHUNKS; i++) {
                if (heads[i].capacity == 0)
                    continue;
                used_chunks++;
                rand = rng(1000);
                if (rand <= head_corrupt_rate) {
                    memset(&heads[i], '=', sizeof(struct lazy_list_head));
                    heads_corrupted++;
                }
            }
        }
    }

    if (dentries_corrupted != 0)
        printf("  - Dentries corrupted: %d/%d.\n", dentries_corrupted, dentries_cnt);
    if (next_corrupted != 0)
        printf("  - Dentry next pointers corrupted: %d/%d.\n", next_corrupted, dentries_cnt);
    if (files_corrupted != 0)
        printf("  - Files inodes corrupted: %d/%d.\n", files_corrupted, file_cnt);
    if (dirs_corrupted != 0)
        printf("  - Directory inodes currupted: %d/%d.\n", dirs_corrupted, dir_cnt);
    if (dc_corrupted != 0)
        printf("  - Datachunks corrupted: %d/%d.\n", dc_corrupted, datachunk_cnt);
    if (data_corrupted != 0)
        printf("  - Data pointers corrupted: %d/%d.\n", data_corrupted, datachunk_cnt);
    if (intervals_corrupted != 0)
        printf("  - Intervals corrupted: %d/%d.\n", intervals_corrupted, datachunk_cnt);
    if (full_dc_corrupted != 0)
        printf("  - Datachunks wiped out: %d/%d.\n", full_dc_corrupted, datachunk_cnt);
    if (heads_corrupted != 0)
        printf("  - Lazy list heads wiped out: %d/%d.\n", heads_corrupted, used_chunks);
    printf("Corruption completed.\n");
}

void print_dentries(struct dfs_inode *inode)
{
    if (!isdir(inode)) {
        printf("Internal error: inode is not directory.\n");
        return;
    }
    struct dfs_dentry *curr_dentry = get_first_dentry(inode);
    printf("\t[");
    while (curr_dentry != NULL) {
        printf("%s", curr_dentry->name);
        if (curr_dentry->list.next != NULL) {
            printf(", ");
        }
        curr_dentry = img_to_mem(curr_dentry->list.next);
    }
    printf("]\n");
}

int count_datachunks(struct dfs_inode *inode)
{
    if (!isreg(inode)) {
        printf("Internal error: inode is not file.\n");
        return -1; 
    }

    int cnt = 0;
    for (int i = 0; i < datachunk_cnt; i++) {
        if (datachunks[i]->parent == unmap_inode(inode)) {
            cnt++;
        }
    }
    return cnt;
}
            
void print_metadata()
{
    printf("Dentries: (%d)\n", dentries_cnt);
    // Print root dentry first:
    printf(" - ROOT [Dentry: %p, Inode: %p]\n", 
                        (dentries[0]), img_to_mem(dentries[0]->inode));
    print_dentries(map_inode(dentries[0]->inode));
    for (int i = 1; i < dentries_cnt; i++) {
        struct dfs_inode *inode = map_inode(dentries[i]->inode);
        printf(" - %s [Dentry: %p, Inode: %p]\n", dentries[i]->name, 
                        (dentries[i]), img_to_mem(dentries[i]->inode));
        if (isdir(inode)) {
            print_dentries(inode); 
        } else if (isreg(inode)) {
            printf("\t# datachunks: %d\n", count_datachunks(inode));            
        }
    }
    printf("Total inodes: %d (%d files + %d directories)\n",
                    file_cnt + dir_cnt, file_cnt, dir_cnt);
    printf("Total datachunks: %d\n", datachunk_cnt);
}

int dfscorrupt_init()
{
    files = malloc(sizeof(struct dfs_inode) * files_size);
    if (!files) 
        return -1;
    dirs = malloc(sizeof(struct dfs_inode) * dirs_size);
    if (!dirs)
        return -1;

    // size * 2 because most dentries have longer names and therefore
    // are 64-byte dentries
    dentries = malloc(sizeof(struct dfs_dentry) * 2 * dentries_size);
    if (!dentries)
        return -1;

    datachunks = malloc(sizeof(struct dfs_datachunk) * datachunks_size);
    if (!datachunks)
        return -1;

    return 0;
}

void dfscorrupt_free()
{
    if (files)
        free(files);
    if (dirs)
        free(dirs);
    if (dentries)
        free(dentries);
    if (datachunks)
        free(datachunks);
}

void print_flags()
{
    printf("Corruption rates: \n");
    printf("Dentry: ");
    if (dentry_corrupt_rate > 0)
        printf("%d/1000. ", dentry_corrupt_rate);
    else
        printf("Not set. ");

    printf("Next: ");
    if (next_corrupt_rate > 0)
        printf("%d/1000. ", next_corrupt_rate);
    else
        printf("Not set. ");

    printf("File: ");
    if (file_corrupt_rate > 0)
        printf("%d/1000. ", file_corrupt_rate);
    else 
        printf("Not set. ");

    printf("Directory: ");
    if (dir_corrupt_rate > 0)
        printf("%d/1000. ", dir_corrupt_rate);
    else
        printf("Not set. ");

    printf("Datachunk: ");
    if (datachunk_corrupt_rate > 0)
        printf("%d/1000. \n\n", datachunk_corrupt_rate);
    else
        printf("Not set.\n\n");
}

void print_usage()
{
    printf("Usage: dfscorrupt [image] [--target rate] [--target rate] ... \n");
    printf("Available targets: \n");
    printf("    dentry: dentry pointer to inode\n"
           "    file: file inode pointer to root datachunk\n"
           "    dir: directory inode pointer to first dentry\n"
           "    datachunk: datachunk pointer to children\n"
           "    next: dentry pointer to next dentry\n"
           "    data: datachunk's data pointer\n"
           "    interval: datachunk's interval values\n"
           "    head: lazy list heads\n"
           "    datachunk-whole: wipe out entire datachunks\n"
           "    bitmap: lazy list bitmaps\n"
          );
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage();
        exit(0);
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
    sb = (struct dfs_fs *)mem;
    image_mem = sb->mem;

    printf("=================== DFSCORRUPT v0.1 ====================\n");
    if (argc == 2) {
        printf("Not corrupting any pointers.\n");
    } else {
        int tmp;
        for (int i = 2; i < argc; i += 2) {
            if (strcmp(argv[i], "--dentry") == 0) {
                if (i + 1 >= argc) {
                    print_usage();
                    exit(0);
                }
                tmp = atoi(argv[i + 1]);
                if (tmp < 0 || tmp > 1000) {
                    printf("Error: corruption rate can only be between 0-1000.\n");
                    exit(1);
                }
                dentry_corrupt_rate = tmp;
            } else if (strcmp(argv[i], "--file") == 0) {
                if (i + 1 >= argc) {
                    print_usage();
                    exit(0);
                }
                tmp = atoi(argv[i + 1]);
                if (tmp < 0 || tmp > 1000) {
                    printf("Error: corruption rate can only be between 0-1000.\n");
                    exit(1);
                }
                file_corrupt_rate = tmp;
            } else if (strcmp(argv[i], "--dir") == 0) {
                if (i + 1 >= argc) {
                    print_usage();
                    exit(0);
                }
                tmp = atoi(argv[i + 1]);
                if (tmp < 0 || tmp > 1000) {
                    printf("Error: corruption rate can only be between 0-1000.\n");
                    exit(1);
                }
                dir_corrupt_rate = tmp;
            } else if (strcmp(argv[i], "--datachunk") == 0) {
                if (i + 1 >= argc) {
                    print_usage();
                    exit(0);
                }
                tmp = atoi(argv[i + 1]);
                if (tmp < 0 || tmp > 1000) {
                    printf("Error: corruption rate can only be between 0-1000.\n");
                    exit(1);
                }
                datachunk_corrupt_rate = tmp;
            } else if (strcmp(argv[i], "--next") == 0) {
                if (i + 1 >= argc) {
                    print_usage();
                    exit(0);
                }
                tmp = atoi(argv[i + 1]);
                if (tmp < 0 || tmp > 1000) {
                    printf("Error: corruption rate can only be between 0-1000.\n");
                    exit(1);
                }
                next_corrupt_rate = tmp;
            } else if (strcmp(argv[i], "--data") == 0) {
                if (i + 1 >= argc) {
                    print_usage();
                    exit(0);
                }
                tmp = atoi(argv[i + 1]);
                if (tmp < 0 || tmp > 1000) {
                    printf("Error: corruption rate can only be between 0-1000.\n");
                    exit(1);
                }
                data_corrupt_rate = tmp;
            } else if (strcmp(argv[i], "--interval") == 0) {
                if (i + 1 >= argc) {
                    print_usage();
                    exit(0);
                }
                tmp = atoi(argv[i + 1]);
                if (tmp < 0 || tmp > 1000) {
                    printf("Error: corruption rate can only be between 0-1000.\n");
                    exit(1);
                }
                interval_corrupt_rate = tmp;
            } else if (strcmp(argv[i], "--datachunk-whole") == 0) {
                if (i + 1 >= argc) {
                    print_usage();
                    exit(0);
                }
                tmp = atoi(argv[i + 1]);
                if (tmp < 0 || tmp > 1000) {
                    printf("Error: corruption rate can only be between 0-1000.\n");
                    exit(1);
                }
                dc_full_corrupt_rate = tmp;
            } else if (strcmp(argv[i], "--head") == 0) {
                if (i + 1 >= argc) {
                    print_usage();
                    exit(0);
                }
                tmp = atoi(argv[i + 1]);
                if (tmp < 0 || tmp > 1000) {
                    printf("Error: corruption rate can only be between 0-1000.\n");
                    exit(1);
                }
                head_corrupt_rate = tmp;
            } else if (strcmp(argv[i], "--bitmap") == 0) {
                if (i + 1 >= argc) {
                    print_usage();
                    exit(0);
                }
                tmp = atoi(argv[i + 1]);
                if (tmp < 0 || tmp > 1000) {
                    printf("Error: corruption rate can only be between 0-1000.\n");
                    exit(1);
                }
                bitmap_corrupt_rate = tmp;
            }
        }
    }

    if (dfscorrupt_init() == -1) {
        printf("Error: failed to allocate memory.\n");
        exit(1);
    }

    // print_flags();

    clock_t begin = clock();

    load_metadata();
    // print_metadata();
    corrupt_metadata();
    
    if (bitmap_corrupt_rate > 0)
        corrupt_bitmap();

    dfscorrupt_free();

    clock_t end = clock();
    double runtime_main = (double)(end - begin) / (CLOCKS_PER_SEC / 1000);
    printf("Total runtime: %.3fms.\n", runtime_main);
    close(fp);

    printf("========================================================\n");
    exit(0);
}
