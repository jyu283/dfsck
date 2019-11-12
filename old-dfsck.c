#include "dfsck.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>

struct stat st;
void *mem; //start of mmaped image
void *image_mem; //where the fs was created
struct dfs_fs *sb; //dfs_fs *dfs in densefs.c is sb in dfsck.c
struct gen_pool *meta_pool, *data_pool;
struct gen_pool_chunk *metachunk, *datachunk;
struct imeta *memimeta_arr;
struct dfs_dentry *root_dentry = NULL;
struct dfs_inode *root_inode = NULL;
unsigned long int sb_size, meta_size, data_size;
void *mem_addrs[16];
size_t file_size;
size_t bitmap_bits, bitmap_bytes, used, bits_allocated;
size_t dbitmap_bits, dbitmap_bytes, d_used, d_bits_allocated;

unsigned long *metaBitmap;
unsigned long *dataBitmap;
struct dentry_item *dentries;
struct inode_item *directories, *files;
struct datachunk_item *chunks;
unsigned long *imageMetaBitmap;
unsigned long *imageDataBitmap;
long unsigned int dentriesAlloc = 1000, directoriesAlloc = 1000, filesAlloc = 1000, chunksAlloc = 1000;
int dentry_count = 0, file_count = 0, dir_count = 0, chunk_count = 0, dentries_traversed = 0, chunks_traversed = 0;

int prevC = 0, nextC = 0, inodeC = 0, dotC = 0, dotdotC = 0, nlinksC = 0, dentryC = 0;

// 2.0 OK
//convert image addrs into mmapped image addrs
void* image_to_mmap(void* addr) {
    if(addr == NULL)
        return NULL;
    unsigned long int int_offset = (unsigned long int)(addr
            - image_mem) / sizeof(unsigned long int);
    return (void*)mem + int_offset*sizeof(unsigned long int);
}

// 2.0 OK
void* mmapToImage(void* addr){
    if(addr == NULL)
        return NULL;
    unsigned long int int_offset = (unsigned long int)(addr 
            - (void*)mem) / sizeof(unsigned long int);
    return image_mem + int_offset*sizeof(unsigned long int);
}

static inline long dfs_inode_get_size(const struct dfs_inode* inode)
{
    return inode->__lock_metaidx_size & LMS_SIZE_MASK;
}

static inline metaidx_t dfs_inode_get_meta_idx(const struct dfs_inode* inode)
{
    return (inode->__lock_metaidx_size & LMS_METAIDX_MASK) >> LMS_METAIDX_POS;
}

static inline void read_imeta(metaidx_t idx, kuid_t* uid, kgid_t* gid, umode_t* mode)
{
    struct imeta* p;
    // dfs_imeta_lock(dfs);
    // DFS_CHECK(idx < dfs->imeta.num);
    p = &((struct imeta*)image_to_mmap((void*)sb->imeta.arr))[idx];
    //used to be p = &sb->imeta.arr[idx]
    if (uid)
        *uid = p->uid;
    if (gid)
        *gid = p->gid;
    if (mode)
        *mode = p->mode;
    // dfs_imeta_unlock(dfs);
}

static inline umode_t inode_mode(const struct dfs_inode* inode)
{
    umode_t mode;
    read_imeta(dfs_inode_get_meta_idx(inode), NULL, NULL, &mode);
    return mode;
}

static inline bool isdir(const struct dfs_inode* inode)
{
    return S_ISDIR(inode_mode(inode));
}

static inline bool isreg(const struct dfs_inode* inode)
{
    return S_ISREG(inode_mode(inode));
}

struct dfs_dentry* mapDentry(void *dentry){
    return (struct dfs_dentry*)image_to_mmap((void*)dentry);
}

struct dfs_inode* mapInode(void *inode){
    return (struct dfs_inode*)image_to_mmap((void*)inode);
}

struct dfs_datachunk* mapDatachunk(void *dc){
    return (struct dfs_datachunk*)image_to_mmap((void*)dc);
}

// 1 = bad, 0 = good
//takes a non tranformed address
int checkMetaAddr(void *addr){
    //checks if address is in appropriate range and alligned
    if(!(metachunk->start_addr <= (unsigned long)addr && 
            (unsigned long)addr < metachunk->end_addr) || (((unsigned long)addr & 31) != 0)){
        //printf("Error: invalid address to meta space\n");
        return 1;
    }
    return 0;
}

int checkDataAddr(void *addr){
    //uses image addresses
    //checks if address is in appropriate range and alligned
    if(!(datachunk->start_addr <= (unsigned long)addr && 
            (unsigned long)addr < datachunk->end_addr) || (((unsigned long)addr & 4095) != 0)){
        //printf("Error: invalid address to data space\n");
        return 1;
    }
    return 0;
}

int checkMetaBitmap(void* addr, int size){
    void *startOfMeta = image_to_mmap((void *)metachunk->start_addr);
    void *endOfMeta = image_to_mmap((void *)metachunk->end_addr);
    unsigned long metaAddr;
    int index; //index of the unsigned long that needs to be updated
    int bit; //the bit that needs to be updated in the long
    
    size = round_up(size,32);
    for(int i = 0; i < size/32; i++){
        if(!(addr >= startOfMeta && addr <= endOfMeta) || ((unsigned long)addr & 31) != 0){
            printf("Error: Address is outside of metachunk.\n");
            return 1;
        }
        metaAddr = addr - startOfMeta;
        index = metaAddr >> 11; 
        bit = (metaAddr >> 5) & 63; 
        if(((metaBitmap[index] >> bit) & 1) == 1){
            printf("Error: Meta space already in use.\n");
            return 1;
        }
        addr = addr + 32;
    }
    return 0;
}

int updateMetaBitmap(void* addr, int size){
    void *startOfMeta = image_to_mmap((void *)metachunk->start_addr);
    void *endOfMeta = image_to_mmap((void *)metachunk->end_addr);
    unsigned long metaAddr;
    int index; //index of the unsigned long that needs to be updated
    int bit; //the bit that needs to be updated in the long
    
    size = round_up(size,32);
    for(int i = 0; i < size/32; i++){
        if(!(addr >= startOfMeta && addr <= endOfMeta) || ((unsigned long)addr & 31) != 0){
            printf("Error: Address is outside of metachunk.\n");
            return 1;
        }
        metaAddr = addr - startOfMeta;
        index = metaAddr >> 11; 
        bit = (metaAddr >> 5) & 63; 
        if(((metaBitmap[index] >> bit) & 1) == 1){
            printf("Error: Meta space already in use.\n");
            return 1;
        }else{
            metaBitmap[index] = metaBitmap[index] | (1ULL << bit);
            bits_allocated++;
        }
        addr = addr + 32;
    }
    return 0;
}

int checkDataBitmap(void* addr, int size){
    void *startOfData = image_to_mmap((void *)datachunk->start_addr);
    void *endOfData = image_to_mmap((void *)datachunk->end_addr);
    unsigned long dataAddr;
    int index; //index of the unsigned long that needs to be updated
    int bit; //the bit that needs to be updated in the long

    size = round_up(size,4096);
    for(int i = 0; i < size/4096; i++){
        if(!(addr >= startOfData && addr <= endOfData) || ((unsigned long)addr & 31) != 0){
            printf("Error: Address is outside of Datachunk.\n");
            return 1;
        }
        dataAddr = addr - startOfData;
        index = dataAddr >> 18; 
        bit = (dataAddr >> 12) & 63;
        if(((dataBitmap[index] >> bit) & 1) == 1){
            printf("Error: Data space already in use.\n");
            return 1;
        }
        addr = addr + 4096;
    }
    return 0;
}

int updateDataBitmap(void* addr, int size){
    void *startOfData = image_to_mmap((void *)datachunk->start_addr);
    void *endOfData = image_to_mmap((void *)datachunk->end_addr);
    unsigned long dataAddr;
    int index; //index of the unsigned long that needs to be updated
    int bit; //the bit that needs to be updated in the long

    size = round_up(size,4096);
    for(int i = 0; i < size/4096; i++){
        if(!(addr >= startOfData && addr <= endOfData) || ((unsigned long)addr & 31) != 0){
            printf("Error: Address is outside of Datachunk.\n");
            return 1;
        }
        dataAddr = addr - startOfData;
        index = dataAddr >> 18; 
        bit = (dataAddr >> 12) & 63;
        if(((dataBitmap[index] >> bit) & 1) == 1){
            printf("Error: Data space already in use.\n");
            return 1;
        }else{
            dataBitmap[index] = dataBitmap[index] | (1ULL << bit);
            d_bits_allocated++;
        }
        addr = addr + 4096;
    }
    return 0;
}

void* memCheck(void* addr,long unsigned int* currSize, int count, long unsigned int size){
    if(count >= *currSize){
        *currSize = *currSize * 2;
        return realloc(addr, *currSize * size);
    }
    return addr;
}

void* selectMajority(void **candidates, int num_candidates){
    void **unique_candidates = calloc(num_candidates,sizeof(void*));
    int *counts = calloc(num_candidates,sizeof(int));
    int highest = -1;
    void *majority;
    int num_unique = 0;
    //counting
    for(int i = 0; i < num_candidates; i++){
        int duplicate = 0;
        for(int j = 0; j < num_unique; j++){
            if(candidates[i] == unique_candidates[j]){
                duplicate = 1;
                counts[j]++;
                break;
            }
        }
        if(!duplicate){
            unique_candidates[num_unique] = candidates[i];
            counts[num_unique]++;
            num_unique++;
        }
    }
    //selection
    for(int i = 0; i < num_unique; i++){
        if(counts[i] > highest){
            highest = counts[i];
            majority = unique_candidates[i];
        }
    }
    free(unique_candidates);
    free(counts);
    return majority;
}

// calculating addresses only using arithmetic, not trusting any pointers from the image yet
void preCalculate() {
    size_t unit, d_unit;
    size_t root_inode_offset;

    file_size = st.st_size;
    sb = (struct dfs_fs *)mem;
    sb_size = DFS_SUPERBLOCK_SIZE;
    meta_size = file_size >> 4;
    data_size = file_size - sb_size - meta_size; 
    metachunk = (struct gen_pool_chunk *)(mem + sb_size);
    datachunk = (struct gen_pool_chunk *)(mem + sb_size + meta_size);

    // FIXME: Change code to work with Matt's new bitmap 
    // Since the bitmap is moved, the root inode offset is going to change accordingly
     
    /*unit = 1ULL << 5;*/
    /*bitmap_bits = DIV_ROUND_UP(8 * (meta_size - sizeof(struct gen_pool_chunk)), (8 * unit) + 1);*/
    /*bitmap_bytes = BITS_TO_LONGS(bitmap_bits) * sizeof(long);*/
    /*used = round_up(sizeof(struct gen_pool_chunk) + bitmap_bytes, unit);*/
    bitmap_bits = DFS_META_NUM_CHUNKS * (DFS_META_FREE_BITMAP + 1);
    bitmap_bytes = BITS_TO_LONGS(bitmap_bits) * sizeof(long);

    d_unit = 1ULL << 12;
    dbitmap_bits = DIV_ROUND_UP(8 * (data_size - sizeof(struct gen_pool_chunk)), (8 * d_unit) + 1);
    dbitmap_bytes = BITS_TO_LONGS(dbitmap_bits) * sizeof(long);
    d_used = round_up(sizeof(struct gen_pool_chunk) + dbitmap_bytes, d_unit);

    //calculating the root inode offset for checking later
    root_inode_offset = sb_size + used + 0x40;
    root_inode = (struct dfs_inode*)(mem + root_inode_offset);
    root_dentry = (struct dfs_dentry*)&sb->rootdir;
    data_pool = (struct gen_pool*)&sb->data_pool;
    meta_pool = (struct gen_pool*)&sb->meta_pool;

    //use all the addresses that should be fixed to find mem, collecting them here
    mem_addrs[0] = sb->mem;
    /*mem_addrs[1] = (void*)sb->meta_pool.chunks.next - sb_size;*/
    /*mem_addrs[2] = (void*)sb->meta_pool.chunks.prev - sb_size;*/
    mem_addrs[3] = (void*)sb->data_pool.chunks.next - sb_size - meta_size;
    mem_addrs[4] = (void*)sb->data_pool.chunks.prev - sb_size - meta_size;
    mem_addrs[5] = (void*)metachunk->next_chunk.next - 0x70;
    mem_addrs[6] = (void*)metachunk->next_chunk.prev - 0x70;
    mem_addrs[7] = (void*)datachunk->next_chunk.next - 0x38;
    mem_addrs[8] = (void*)datachunk->next_chunk.prev - 0x38;
    mem_addrs[9] = (void*)root_inode->dot_dents[0].inode - root_inode_offset;
    mem_addrs[10]= (void*)root_inode->dot_dents[1].inode - root_inode_offset;
    mem_addrs[11]= (void*)sb->rootdir.inode - root_inode_offset;
    mem_addrs[12]= (void*)metachunk->start_addr - sb_size - used;
    mem_addrs[13]= (void*)metachunk->end_addr - sb_size - meta_size + 1;
    mem_addrs[14]= (void*)datachunk->start_addr - sb_size - meta_size - d_used;
    mem_addrs[15]= (void*)datachunk->end_addr - sb_size - meta_size - data_size + 1;

    // for (int i = 0; i < 16; i++){
    //     printf("%d : %p\n", i, mem_addrs[i]);
    // }
    
    image_mem = selectMajority(mem_addrs,16);
    memimeta_arr = (struct imeta*)image_to_mmap((void*)sb->imeta.arr);

    imageMetaBitmap = (unsigned long*)(mem + sb_size + sizeof(struct gen_pool_chunk));
    imageDataBitmap = (unsigned long*)(mem + sb_size + meta_size + sizeof(struct gen_pool_chunk));
}

// FIXME: Metabitmap needs to change?
void initTables(){
    //all the tables to store the data that was found
    dentries = malloc(dentriesAlloc * sizeof(struct dentry_item));
    directories = malloc(directoriesAlloc * sizeof(struct inode_item));
    files = malloc(filesAlloc * sizeof(struct inode_item));
    chunks = malloc(chunksAlloc * sizeof(struct datachunk_item));
    metaBitmap = calloc(DIV_ROUND_UP(bitmap_bytes, sizeof(unsigned long)), sizeof(unsigned long));
    dataBitmap = calloc(DIV_ROUND_UP(dbitmap_bytes,sizeof(unsigned long)), sizeof(unsigned long));
}

void checkRootInode(){

    if(root_inode->pincount.refs.counter != 0){
        root_inode->pincount.refs.counter = 0;
    }

    if(checkMetaAddr(root_inode->data.dirents.first) && root_inode->data.dirents.first != NULL){
        root_inode->data.dirents.first = NULL;
        printf("Error: Root Inode data bad.\n");
        dentryC++;
    }
    //. entry
    if(root_inode->dot_dents[0].list.next != NULL ||
            root_inode->dot_dents[0].list.pprev != NULL){
        root_inode->dot_dents[0].list.next = NULL;
        root_inode->dot_dents[0].list.next = NULL;
    }
    
    if(mmapToImage(root_inode) != root_inode->dot_dents[0].inode){
        root_inode->dot_dents[0].inode = mmapToImage(root_inode);
    }

    if(root_inode->dot_dents[0].namelen != 1){
        root_inode->dot_dents[0].namelen = 1;
    }
    
    if(strcmp(root_inode->dot_dents[0].name, ".")){
        strcpy(root_inode->dot_dents[0].name,".");
    }
    //.. entry
    if(root_inode->dot_dents[1].list.next != NULL ||
            root_inode->dot_dents[1].list.pprev != NULL){
        root_inode->dot_dents[1].list.next = NULL;
        root_inode->dot_dents[1].list.next = NULL;
    }
    
    if(mmapToImage(root_inode) != root_inode->dot_dents[1].inode){
        root_inode->dot_dents[1].inode = mmapToImage(root_inode);
    }

    if(root_inode->dot_dents[1].namelen != 2){
        root_inode->dot_dents[1].namelen = 2;
    }
    if(strcmp(root_inode->dot_dents[1].name, "..")){
        strcpy(root_inode->dot_dents[1].name,"..");
    }
}

void checkRootDentry(){

    if(root_dentry->list.next != (void*)0x3c3c3c3c3c3c3c3c){
        printf("Error: root dentry next isn't 3c3c3c3c3c3c3c3c\n");
        root_dentry->list.next = (void*)0x3c3c3c3c3c3c3c3c;
    }
    if(root_dentry->list.pprev != (void*)0x3c3c3c3c3c3c3c3c){
        printf("Error: root dentry prev isn't 3c3c3c3c3c3c3c3c\n");
        root_dentry->list.pprev = (void*)0x3c3c3c3c3c3c3c3c;
    }
    if(root_dentry->inode != mmapToImage(root_inode)){
        printf("Error: root inode addr wrong\n");
        root_dentry->inode = mmapToImage(root_inode);
    }

    checkRootInode();
    //check refs is valid (currently unused?)
    if (root_dentry->refs.refcount.refs.counter != 1010580540) {
        printf("Error: wrong rootdir refcount\n");
        root_dentry->refs.refcount.refs.counter = 1010580540;
    }
    if (root_dentry->namelen != 0) {
        printf("Error: namelen is invalid\n");
        root_dentry->namelen = 0;
    }
    if (root_dentry->name[0] != '\0') {
        printf("Error: rootdir name invalid\n");
        root_dentry->name[0] = '\0';
    }
}

void checkDataPool(){

    if(data_pool->lock.rlock.raw_lock.lock != 0){
        printf("Error: data_pool lock isn't 0\n");
        data_pool->lock.rlock.raw_lock.lock = 0;
    }
    if (data_pool->chunks.next != image_mem + sb_size + meta_size) {
        printf("Error: data_pool chunk next wrong addr\n");
        data_pool->chunks.next = image_mem + sb_size + meta_size;
    }
    if (data_pool->chunks.prev != image_mem+ sb_size + meta_size) {
        printf("Error: data_pool chunk prev wrong addr\n");
        data_pool->chunks.prev = image_mem+ sb_size + meta_size;
    }
    if (data_pool->min_alloc_order != 12) {
        printf("Error: data alloc order isn't 12\n");
        data_pool->min_alloc_order = 12;
    }
    //IGNORING ALGO
    if (data_pool->data != NULL){
        printf("Error: data_pool data incorrect\n");
        data_pool->data = NULL;
    }
    if (data_pool->name != NULL){
        printf("Error: data_pool name incorrect\n");
        data_pool->name = NULL;
    }
}

void checkMetaPool(){
    
    if(meta_pool->lock.rlock.raw_lock.lock != 0){
        printf("Error: meta_pool lock isn't 0\n");
        meta_pool->lock.rlock.raw_lock.lock = 0;
    }
    if (meta_pool->chunks.next != image_mem + sb_size) {
        printf("Error: meta_pool chunk next wrong addr\n");
        meta_pool->chunks.next = image_mem + sb_size;
    }
    if (meta_pool->chunks.prev != image_mem + sb_size) {
        printf("Error: meta_pool chunk prev wrong addr\n");
        meta_pool->chunks.prev = image_mem + sb_size;
    }
    if (meta_pool->min_alloc_order != 5) {
        printf("Error: meta alloc order isn't 5\n");
        meta_pool->min_alloc_order = 5;
    }
    //IGNORING ALGO
    if (meta_pool->data != NULL){
        printf("Error: meta_pool data incorrect\n");
        meta_pool->data = NULL;
    }
    if (meta_pool->name != NULL){
        printf("Error: meta_pool name incorrect\n");
        meta_pool->name = NULL;
    }
}

void checkImetaArr(){
    //there is more to check, these are just the default ones
    if (memimeta_arr[0].mode != (S_IFDIR|01777)
            || memimeta_arr[0].uid.val != 0
            || memimeta_arr[0].gid.val != 0) {
        printf("Error: imeta array 0 invalid\n");
        memimeta_arr[0].mode = (S_IFDIR|01777);
        memimeta_arr[0].uid.val = 0;
        memimeta_arr[0].gid.val = 0;
    }
    if (memimeta_arr[1].mode != (S_IFDIR|00755)
            || memimeta_arr[1].uid.val != 0
            || memimeta_arr[1].gid.val != 0) {
        printf("Error: imeta array 1 invalid\n");
        memimeta_arr[1].mode = (S_IFDIR|00755);
        memimeta_arr[1].uid.val = 0;
        memimeta_arr[1].gid.val = 0;
    }
    if (memimeta_arr[2].mode != (S_IFREG|00644)
            || memimeta_arr[2].uid.val != 0
            || memimeta_arr[2].gid.val != 0) {
        printf("Error: imeta array 2 invalid\n");
        memimeta_arr[2].mode = (S_IFREG|00644);
        memimeta_arr[2].uid.val = 0;
        memimeta_arr[2].gid.val = 0;
    }
}

void checkSuperblock(){

    checkRootDentry();

    if(sb->mem != image_mem){
        printf("Error: incorrect mem in superblock\n");
        sb->mem = image_mem;
    }

    if (sb->size != file_size) {
        printf("Error: wrong sb size: sb %dB vs st %dB\n", (int)sb->size, (int)st.st_size);
        sb->size = file_size;
    }
    
    checkDataPool();
    checkMetaPool();

    if (sb->ino_key != 0x3c3c3c3c3c3c3c3c) {
        printf("Error: ino_key isn't 3c3c3c3c3c3c3c3c\n");
        sb->ino_key = 0x3c3c3c3c3c3c3c3c;
    }

    //TODO: num in the imeta struct
    checkImetaArr();
    updateMetaBitmap(memimeta_arr,64);

    if(sb->imeta.lock.rlock.raw_lock.lock != 0){
        printf("Error: imeta lock is not 0\n");
        sb->imeta.lock.rlock.raw_lock.lock = 0;
    }    

    if(sb->data_alloc_lock.rlock.raw_lock.lock != 0){
        printf("Error: data_alloc_lock is not 0\n");
        sb->data_alloc_lock.rlock.raw_lock.lock = 0;
    }

    if(sb->meta_alloc_lock.rlock.raw_lock.lock != 0){
        printf("Error: meta_alloc_lock is not 0\n");
        sb->meta_alloc_lock.rlock.raw_lock.lock = 0;
    }

    if(sb->rename_lock.rlock.raw_lock.lock != 0){
        printf("Error: rename_lock is not 0\n");
        sb->rename_lock.rlock.raw_lock.lock = 0;
    }
}

void checkMetaChunk(){
    //TODO unchecked: phys_addr, avail(can only be done at the end of checking)
    if (metachunk->next_chunk.next != image_mem + 0x70) {
        printf("Error: wrong meta_chunk next\n");
        metachunk->next_chunk.next = image_mem + 0x70;
    } 
    if (metachunk->next_chunk.prev != image_mem + 0x70) {
        printf("Error: wrong meta_chunk prev\n");
        metachunk->next_chunk.prev = image_mem + 0x70;
    }
    if (metachunk->internal != 1) {
        printf("Error: meta internal isn't 1\n");
        metachunk->internal = 1;
    }
    //check if start_addr is correct(right after bitmap ends)
    if (metachunk->start_addr != (long unsigned int)(image_mem + sb_size + used)) {
        printf("Error: metaspace doesn't start at correct addr\n");
        metachunk->start_addr = (long unsigned int)(image_mem + sb_size + used);
    }
    //check if end_addr is correct (1 byte before data start)
    if (metachunk->end_addr != (long unsigned int)(image_mem + sb_size + meta_size - 1)) {
        printf("Error: metaspace doesn't end at correct addr\n");
        metachunk->end_addr = (long unsigned int)(image_mem + sb_size + meta_size - 1);
    }
}

void checkDataChunk(){
    //TODO unchecked: phys_addr, avail(can only be done at the end of checking)
    if (datachunk->next_chunk.next != image_mem + 0x38) {
        printf("Error: wrong data_chunk next\n");
        datachunk->next_chunk.next = image_mem + 0x38;
    } 
    if (datachunk->next_chunk.prev != image_mem + 0x38) {
        printf("Error: wrong data_chunk prev\n");
        datachunk->next_chunk.prev = image_mem + 0x38;
    }
    if (datachunk->internal != 1) {
        printf("Error: data internal isn't 1\n");
        datachunk->internal = 1;
    }   
    if (datachunk->start_addr != (long unsigned int)(image_mem + sb_size + meta_size + d_used)) {
        printf("Error: dataspace doesn't start at correct addr\n");
        datachunk->start_addr = (long unsigned int)(image_mem + sb_size + meta_size + d_used);
    }
    if (datachunk->end_addr != (long unsigned int)(image_mem + sb_size + meta_size + data_size - 1)) {
        printf("Error: dataspace doesn't end at correct addr\n");
        datachunk->end_addr = (long unsigned int)(image_mem + sb_size + meta_size + data_size - 1);
    }
}

void fixDirInode(struct dfs_inode *currInode, struct dfs_inode *PInode){


    if((currInode->__lock_metaidx_size & LMS_LOCKMASK) != 0){
        printf("Error: Inode lock bit is not 0\n");
        currInode->__lock_metaidx_size =  currInode->__lock_metaidx_size & ~LMS_LOCKMASK;
    }
    if(currInode->pincount.refs.counter != 0){
        printf("Error: Inode pincount is not 0\n");
        currInode->pincount.refs.counter = 0;
    }
    if(checkMetaAddr(currInode->data.dirents.first) && currInode->data.dirents.first != NULL){
        printf("Error: Inode points to invalid dentry addr\n");
        currInode->data.dirents.first = NULL;
        dentryC++;
    }
    //. entry
    if(currInode->dot_dents[0].list.next != NULL ||
            currInode->dot_dents[0].list.pprev != NULL){
        printf("Error: Inode . dentry next and prev is wrong\n");
        currInode->dot_dents[0].list.next = NULL;
        currInode->dot_dents[0].list.pprev = NULL;
    }
    if(mmapToImage(currInode) != currInode->dot_dents[0].inode){
        printf("Error: Inode . dentry has incorrect inode addr\n");
        currInode->dot_dents[0].inode = mmapToImage(currInode);
        dotC++;
    }
    if(currInode->dot_dents[0].namelen != 1){
        printf("Error: Inode . dentry has incorrect namelen\n");
        currInode->dot_dents[0].namelen = 1;
    }
    if(strcmp(currInode->dot_dents[0].name, ".")){
        printf("Error: Inode . dentry has incorrect name\n");
        strcpy(currInode->dot_dents[0].name,".");
    }
    //.. entry
    if(currInode->dot_dents[1].list.next != NULL ||
            currInode->dot_dents[1].list.pprev != NULL){
        printf("Error: Inode .. dentry next and prev is wrong\n");
        currInode->dot_dents[1].list.next = NULL;
        currInode->dot_dents[1].list.pprev = NULL;
    }       
    if(mmapToImage(PInode) != currInode->dot_dents[1].inode){
        printf("Error: Inode .. dentry has incorrect inode addr\n");
        currInode->dot_dents[1].inode = mmapToImage(PInode);
        dotdotC++;
    }
    if(currInode->dot_dents[1].namelen != 2){
        printf("Error: Inode .. dentry has incorrect namelen\n");
        currInode->dot_dents[1].namelen = 2;
    }
    if(strcmp(currInode->dot_dents[1].name, "..")){
        printf("Error: Inode .. dentry has incorrect name\n");
        strcpy(currInode->dot_dents[1].name,"..");
    }
}

int checkDirInode(struct dfs_inode *currInode, struct dfs_inode *PInode){

    if(checkMetaBitmap(currInode,96)){
        return 1;
    }

    int inode_err_count = 0;
    // if((currInode->__lock_metaidx_size & LMS_LOCKMASK) != 0){
    //     inode_err_count++;
    // }
    if(currInode->pincount.refs.counter != 0){
        inode_err_count++;
    }

    if(checkMetaAddr(currInode->data.dirents.first) && currInode->data.dirents.first != NULL){
        inode_err_count++;
    }
    //. entry
    if(currInode->dot_dents[0].list.next != NULL ||
            currInode->dot_dents[0].list.pprev != NULL){
        inode_err_count++;
    }
    //increase weight
    if(mmapToImage(currInode) != currInode->dot_dents[0].inode){
        inode_err_count++;
    }
    if(currInode->dot_dents[0].namelen != 1){
        inode_err_count++;
    }
    //more weight . and .. entries
    if(strcmp(currInode->dot_dents[0].name, ".")){
        inode_err_count++;
    }
    //.. entry
    if(currInode->dot_dents[1].list.next != NULL ||
            currInode->dot_dents[1].list.pprev != NULL){
        inode_err_count++;
    }       
    if(mmapToImage(PInode) != currInode->dot_dents[1].inode){
        inode_err_count++;
    }
    if(currInode->dot_dents[1].namelen != 2){
        inode_err_count++;
    }
    if(strcmp(currInode->dot_dents[1].name, "..")){
        inode_err_count++;
    }
    if(inode_err_count >= 6){
        return 1;
    }
    //getting here means this inode is not too corrupted
    //so we should try fixing it
    fixDirInode(currInode, PInode);
    return 0;
    //anything we can do to check time?
    //whats up with pincount?
    //lock should be released, can check if the metaidx is in range/exists
}

void fixFileInode(struct dfs_inode *currInode){

    if(currInode->nlink != 1){
        printf("Error: File inode incorrect nlinks\n");
        currInode->nlink = 1;
        nlinksC++;
    }
    if((currInode->__lock_metaidx_size & LMS_LOCKMASK) != 0){
        printf("Error: File inode lock bit is not 0\n");
        currInode->__lock_metaidx_size =  currInode->__lock_metaidx_size & ~LMS_LOCKMASK;
    }
    if(currInode->pincount.refs.counter != 0){
        printf("Error: File inode pincount is not 0\n");
        currInode->pincount.refs.counter = 0;
    }
    if(checkMetaAddr(currInode->data.chunks.rb_node) && currInode->data.chunks.rb_node != NULL){
        printf("Error: File inode points to invalid datachunk addr\n");
        currInode->data.chunks.rb_node = NULL;
    }
}

int checkFileInode(struct dfs_inode *currInode){

    if(checkMetaBitmap(currInode,32)){
        return 1;
    }

    int inode_err_count = 0;
    if(currInode->nlink != 1){
        inode_err_count++;
    }
    // if((currInode->__lock_metaidx_size & LMS_LOCKMASK) != 0){
    //     inode_err_count++;
    // }
    if(currInode->pincount.refs.counter != 0){
        inode_err_count++;
    }
    if(checkMetaAddr(currInode->data.chunks.rb_node) && currInode->data.chunks.rb_node != NULL){
        inode_err_count++;
    }
    if(inode_err_count >= 2){
        return 1;
    }
    //getting here means this inode is not too corrupted
    //so we should try fixing it
    fixFileInode(currInode);
    return 0;
}

void fixDentry(struct dfs_dentry *currDentry, void **prevDentry){

    if(currDentry->list.pprev != mmapToImage(prevDentry)){
        printf("Error: Wrong prev %p %p address for dentry\n", currDentry->list.pprev, mmapToImage(prevDentry));
        currDentry->list.pprev = mmapToImage(prevDentry);
        prevC++;
    }
    if(checkMetaAddr(currDentry->list.next) && currDentry->list.next != NULL){
        printf("Error: Invalid next address for dentry\n");
        currDentry->list.next = NULL;
        nextC++;
    }
    if(currDentry->refs.refcount.refs.counter != 1){
        printf("Error: Dentry refs does not equal 1\n");
        currDentry->refs.refcount.refs.counter = 1;
    }

    int namelen = currDentry->namelen;
    //checking if name is actually shorter than what name length indicates
    for(int i = 0; i < namelen; i++){
        if(currDentry->name[i] == '\0'){
            printf("Error: Dentry name is shorter than what namelen says\n");
            currDentry->namelen = i;
            break;
        }
    }
    if(currDentry->name[currDentry->namelen] != '\0'){
        printf("Error: Dentry namelen and name length don't match\n");
        currDentry->name[currDentry->namelen] = '\0';
    }
}

//2 = should stop traversing this dentry list
//1 = skip just this dentry and change corresponding next and prev pointers to modifiy the dentry linked list
//0 = dentry and inode are both good
int checkDentry(struct dfs_dentry *currDentry, void **prevDentry, struct dfs_inode *PInode){

    if(checkMetaAddr(currDentry)){
        printf("Error: Invalid address dentry address\n");
        dentryC++;
        return 2;
    }

    int err_count = 0;
    int inode_err_code = 0;
    currDentry = mapDentry(currDentry);
    struct dfs_inode *currInode = mapInode(currDentry->inode);

    int dentry_size = 30 + currDentry->namelen;
    if(checkMetaBitmap(currDentry,dentry_size)){
        return 2;
    }

    if(mmapToImage(prevDentry) != currDentry->list.pprev){
        err_count++;
    }
    if(currDentry->refs.refcount.refs.counter != 1){
        err_count++;
    }
    if(currDentry->namelen == 0){
        err_count++;
    }
    if(currDentry->name[currDentry->namelen] != '\0'){
        err_count++;
    }
    if(err_count >= 3){ //we can change this number later
        printf("Error: Corrupted dentry\n");
        return 2;
    }
    //done checking if this dentry is even a valid one
    //now checking if it has a proper inode, if the inode is messed up then no point in having a dentry
    if(checkMetaAddr(currDentry->inode)){
        printf("Error: Dentry has an invalid inode address\n");
        inodeC++;
        return 1;
    }

    if(isdir(currInode)){
        inode_err_code = checkDirInode(currInode, PInode);
    }
    else if(isreg(currInode)){
        inode_err_code = checkFileInode(currInode);
    }
    else{
        printf("Error: Inode is not direcory inode or file inode\n");
        return 1;
    }

    if(inode_err_code){
        printf("Error: Courrupred Inode\n");
        return 1;
    }

    //getting this far means the dentry and Inode are both (almost?) good and not some garbage
    //so lets try to fix as much as possible
    fixDentry(currDentry, prevDentry);
    return 0;
}

void insertDentry(struct dfs_dentry *dentry, int pInodeIndex){
    //check if there is enough space to insert
    dentries = (struct dentry_item*)memCheck(dentries, &dentriesAlloc, dentry_count, sizeof(struct dentry_item));
    dentries[dentry_count].dentry = dentry;
    dentries[dentry_count].pInodeIndex = pInodeIndex;
    //dentries[dentry_count].prev = mmapToImage(prev);
    int dentry_size = 30 + dentry->namelen;
    updateMetaBitmap(dentry,dentry_size);
    struct dfs_inode* inode = mapInode(dentry->inode);
    if(isdir(inode)){
        updateMetaBitmap(inode,96);
    }else{
        updateMetaBitmap(inode,32);
    }
    dentry_count++;
}

void insertDirInode(struct dfs_inode *inode, int pInodeIndex){
    
    struct dfs_dentry *currDentry;
    void **prevDentry;
    int ret_val;
    //checks if there is enough space to insert
    directories = (struct inode_item*)memCheck(directories, &directoriesAlloc, dir_count, sizeof(struct inode_item));
    directories[dir_count].inode = inode;
    directories[dir_count].pInodeIndex = pInodeIndex;
    directories[pInodeIndex].nlink_count++;
    directories[dir_count].nlink_count = 2;     //one for being the child of something and one for . entry

    currDentry = (struct dfs_dentry*)inode->data.dirents.first;
    prevDentry = (void **)&(inode->data.dirents.first);
    while(currDentry != NULL){
        ret_val = checkDentry(currDentry, prevDentry, inode);
        currDentry = mapDentry(currDentry);
        if(ret_val == 2){
            *prevDentry = NULL;
            break;
        }
        else if(ret_val == 1){
            *prevDentry = currDentry->list.next; //abusing the fact that the first 8 bytes of prevDentry point to next
            //prevDentry itself stays unchanged
            currDentry = (struct dfs_dentry*)currDentry->list.next;
        }
        else if(ret_val == 0){
            insertDentry(currDentry, dir_count);
            prevDentry = (void **)currDentry;
            currDentry = (struct dfs_dentry*)currDentry->list.next;
        }
    }
    dir_count++;
}

void insertDatachunk(struct dfs_datachunk *datachunk){
    //checks if there is enough space to insert
    chunks = (struct datachunk_item*)memCheck(chunks, &chunksAlloc, chunk_count, sizeof(struct datachunk_item));
    chunks[chunk_count].datachunk = datachunk;
    updateMetaBitmap(datachunk,64);
    unsigned long int size = datachunk->it.last - datachunk->it.start + 1;
    updateDataBitmap(image_to_mmap(datachunk->data),size);
    chunk_count++;
}

int checkDatachunk(struct dfs_datachunk *currDatachunk, unsigned long parent){
    //find all the reasons we can say that this datachunk is just garbage or that it is messed up
    if(checkMetaAddr(mmapToImage(currDatachunk))){
        return 1;
    }
    if(checkMetaBitmap(currDatachunk,64)){
        return 1;
    }
    unsigned long int size = currDatachunk->it.last - currDatachunk->it.start + 1;
    if(checkDataBitmap(image_to_mmap(currDatachunk->data),size)){
        return 1;
    }
    if(checkDataAddr(currDatachunk->data)){
        return 1;
    }
    int err_count = 0;
    if(currDatachunk->initialized != 1){
        err_count++;
    }
    //can do a deeper check to analyze if the red balck tree is proper
    if(currDatachunk->it.rb.__rb_parent_color != parent + 1 && currDatachunk->it.rb.__rb_parent_color != parent){
        err_count++;
    }
    if(checkMetaAddr(currDatachunk->it.rb.rb_left) && currDatachunk->it.rb.rb_left != NULL){
        err_count++;
    }
    if(checkMetaAddr(currDatachunk->it.rb.rb_right) && currDatachunk->it.rb.rb_right != NULL){
        err_count++;
    }
    if(currDatachunk->it.last <= currDatachunk->it.start){
        err_count++;
    }
    //should be one more check to see if it agrees with parent
    if(err_count >= 1){
        return 1;
    }
    return 0;
}

int traverseIT(struct dfs_datachunk *currDatachunk, unsigned long parent){
    //checking

    if(currDatachunk == NULL){
        return 0;
    }
    if(checkDatachunk(currDatachunk, parent)){
        return 1;
    }
    unsigned long left_ret = 0;
    unsigned long right_ret = 0;
    if(parent == 0){
        files[file_count].dataIndex = chunk_count;
    }
    left_ret = traverseIT(mapDatachunk(currDatachunk->it.rb.rb_left), (unsigned long)mmapToImage(currDatachunk));
    insertDatachunk(currDatachunk);
    right_ret = traverseIT(mapDatachunk(currDatachunk->it.rb.rb_right), (unsigned long)mmapToImage(currDatachunk));
    return left_ret + right_ret;
}

void fixDatachunks(int dataIndex){

    unsigned long int currOffset = 0;
    struct dfs_datachunk *currDatachunk;
    while(dataIndex < chunk_count){
        currDatachunk = chunks[dataIndex].datachunk;
        unsigned long int start = currDatachunk->it.start;
        unsigned long int last = currDatachunk->it.last;
        if(start != currOffset){
            printf("Error: Start and last values of a datachunk had to be updated\n");
            currDatachunk->it.start = currOffset;
            currDatachunk->it.last = last - start + currOffset;
        }
        currOffset = currOffset + last - start + 1;
        dataIndex++;
    }
}

void insertFileInode(struct dfs_inode *inode, int pInodeIndex){
    //checks if there is enough space to insert
    files = (struct inode_item*)memCheck(files, &filesAlloc, file_count, sizeof(struct inode_item));
    files[file_count].inode = inode;
    files[file_count].pInodeIndex = pInodeIndex;
    files[file_count].nlink_count++;
    files[file_count].dataIndex = -1;
    //add datachunks to the chunks array//should be a traversel here
    struct dfs_datachunk *currDatachunk = mapDatachunk(inode->data.chunks.rb_node);
    if(currDatachunk != NULL){
        //At this point we assume that all the datachunks we added to the array are completely proper
        //So no need to check them if there wasn't a problem with the traversal
        int traverse_ret = traverseIT(currDatachunk, 0);
        if(traverse_ret && files[file_count].dataIndex == -1){
            //Root was corrupted
            inode->data.chunks.rb_node = NULL;
        }else if(traverse_ret){
            fixDatachunks(files[file_count].dataIndex);
        }
    }
    file_count++;
}

void insertRootDentry(){
    dentries[0].dentry = root_dentry;
    dentry_count++;
    dentries_traversed++;
    updateMetaBitmap(mapInode(root_dentry->inode),96);
    insertDirInode(mapInode(root_dentry->inode),0); //0 because root is its own parent
}

void checkNlinks(){

    for(int i = 0; i < dir_count; i++){
        if(directories[i].nlink_count != directories[i].inode->nlink){
            printf("Error: Directory inode incorrect nlink\n");
            directories[i].inode->nlink = directories[i].nlink_count;
        }
    }
}

void checkMetaData(){
    
    insertRootDentry();
    struct dfs_inode *currInode;
    int currPInodeIndex;
    while(dentries_traversed < dentry_count){
        currInode = mapInode(dentries[dentries_traversed].dentry->inode);
        currPInodeIndex = dentries[dentries_traversed].pInodeIndex;
        if (isdir(currInode)) {
            insertDirInode(currInode, currPInodeIndex);
        } else if (isreg(currInode)) {
            insertFileInode(currInode, currPInodeIndex);
        } else{
            printf("Error: Bad Inode\n");
        }
        dentries_traversed++;
    }
    checkNlinks();
}

void checkBitmaps(){

    int meta_bitmap_size = DIV_ROUND_UP(bitmap_bytes,sizeof(unsigned long));
    double numMetaDiff = 0;
    double numMetaTotal = 0;

    for (int i = 0; i < meta_bitmap_size; i++){
        for(int j = 0; j < 8; j++){
            if(((imageMetaBitmap[i] >> j) & 1) == 1){
                numMetaTotal++;
            }
        }
    }

    for (int i = 0; i < meta_bitmap_size; i++){
        if(metaBitmap[i] != imageMetaBitmap[i]){
            //printf("Error: Metadata bitmap does not match image meta data bitmap\n");
            for(int j = 0; j < 8; j++){
                if(((metaBitmap[i] >> j) & 1) != ((imageMetaBitmap[i] >> j) & 1)){
                    numMetaDiff++;
                }
            }
            imageMetaBitmap[i] = metaBitmap[i];
        }
    }

    printf("Meta Bitmap lost: %f\n", ((double)numMetaDiff/numMetaTotal) * 100);

    if(numMetaDiff){
        printf("Number of metadata bitmap bits that do not match: %f\n", numMetaDiff);
    }
    int data_bitmap_size = DIV_ROUND_UP(dbitmap_bytes,sizeof(unsigned long));
    int numDataDiff = 0;
    for (int i = 0; i < data_bitmap_size; i++){
        if(dataBitmap[i] != imageDataBitmap[i]){
            printf("Error: Data bitmap does not match image data bitmap\n");
            for(int j = 0; j < 8; j++){
                if(((dataBitmap[i] >> j) & 1) != ((imageDataBitmap[i] >> j) & 1)){
                    numDataDiff++;
                }
            }
            imageDataBitmap[i] = dataBitmap[i];
        }
    }
    if(numDataDiff){
        printf("Number of datadata bitmap bits that do not match: %d\n", numDataDiff);
    }
}

void updateAvail(){

    int metaFreeBytes = (bitmap_bits - bits_allocated - 1)*32;
    //printf("metadata free: %d\n", metaFreeBytes);
    if(metaFreeBytes != metachunk->avail.counter){
        printf("Error: Meta space available does not match\n");
        metachunk->avail.counter = metaFreeBytes;
    }

    int dataFreeBytes = (dbitmap_bits - d_bits_allocated - 1)*4096;
    //printf("datadata free: %d\n", dataFreeBytes);
    if(dataFreeBytes != datachunk->avail.counter){
        printf("Error: Data space available does not match\n");
        datachunk->avail.counter = dataFreeBytes;
    }
}

void freeAll(){

    free(metaBitmap);
    free(dataBitmap);
    free(dentries);
    free(directories);
    free(files);
    free(chunks);
}

int main(int argc, char *argv[]) {

    // check if I have an image
    if (argc != 2) {
        fprintf(stderr, "Please provide a denseFS image.\n");
        exit(1);
    }

    // open the FS image
    int fp = open(argv[1], O_RDWR);
    if (fp < 0) {
        fprintf(stderr, "DenseFS image can't be opened.\n");
        exit(1);
    }

    // get some simple image file details
    if (stat(argv[1], &st) != 0) {
        fprintf(stderr, "DenseFS image file details unaccessible.\n");
        exit(1);
    }

    //mmap the entire image into memory
    mem = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fp, 0);
    if (mem == NULL) {
        printf("Couldn't mmap the DenseFS image.\n");
        exit(1);
    }
    
    preCalculate();
    initTables();
    checkSuperblock();
    checkMetaChunk();
    checkDataChunk();
    checkMetaData();
    checkBitmaps();
    updateAvail();
    freeAll();

    printf("Number of Inode pointers corrupted: %d\n", inodeC);
    printf("Number of Dentry pointers corrupted: %d\n", dentryC);
    printf("Number of Prev pointers corrupted: %d\n", prevC);
    printf("Number of Next pointers corrupted: %d\n", nextC);
    printf("Number of nlinks corrupted: %d\n", nlinksC);
    printf("Number of . entries corrupted: %d\n", dotC);
    printf("Number of .. entries corrupted: %d\n", dotdotC);
    close(fp);

    exit(0);
}
