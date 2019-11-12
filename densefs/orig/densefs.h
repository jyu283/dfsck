#ifndef _LINUX_DENSEFS_H
#define _LINUX_DENSEFS_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/kref.h>

struct dfs_inode;
struct fd;
struct linux_dirent;

struct dfs_file {
	off_t offset;
	struct dfs_inode* inode;
	struct kref count;
};

extern struct dfs_inode* dfs_get_root_inode(void);

/*
 * For use when determining the 'start' argument (the directory to do path
 * lookup relative to) from a dfs_file*, which may be NULL to indicate that
 * lookup should start at the densefs root.
 */
static inline struct dfs_inode* dfs_file_inode(struct dfs_file* file)
{
	return file ? file->inode : NULL;
}

bool dfs_isdir(const struct dfs_inode* inode);
struct dfs_inode* dfs_lookup_path(struct dfs_inode* start, const char* path);

struct dfs_file* dfs_openat(struct dfs_inode* start, const char* path, int flags, mode_t mode);
int dfs_close(struct dfs_file* file);
int dfs_stat(struct dfs_inode* start, const char* path, struct kstat* st);
int dfs_getdents(struct dfs_file* file, struct linux_dirent __user* dirp,
                 unsigned int count);
int dfs_utimensat(struct dfs_inode* file, const char* path, struct timespec* times, int flags);
int dfs_mkdirat(struct dfs_inode* start, const char* path, mode_t mode);
int dfs_renameat(struct dfs_inode* ostart, const char* oldpath, struct dfs_inode* nstart, const char* newpath);
int dfs_linkat(struct dfs_inode* ostart, const char* oldpath, struct dfs_inode* nstart, const char* newpath);
ssize_t dfs_write(struct dfs_file* file, const void __user* buf, size_t count);
ssize_t dfs_read(struct dfs_file* file, void __user* buf, size_t count);
off_t dfs_lseek(struct dfs_file* file, off_t offset, int whence);
int dfs_unlink(struct dfs_inode* start, const char* path, int flags);
int dfs_fallocate(struct dfs_file* file, int mode, off_t offset, off_t len);
int dfs_ftruncate(struct dfs_file* file, loff_t length);
int dfs_fchmod(struct dfs_file* file, umode_t mode);
int dfs_fchown(struct dfs_file* file, uid_t uid, gid_t gid);
int dfs_chmod(struct dfs_inode* inode, umode_t mode);
int dfs_chown(struct dfs_inode* inode, uid_t uid, gid_t gid);
int dfs_fchown(struct dfs_file* file, uid_t uid, gid_t gid);
int dfs_statfsat(struct dfs_inode* start_ignored, const char* path_ignored,
                 struct kstatfs *st);

int dfs_getcwd(struct dfs_inode* pwd, char __user* buf, size_t buflen);

void dfs_pin_inode(struct dfs_inode* inode);
void dfs_unpin_inode(struct dfs_inode* inode);

/* On success, caller must unpin *start and putname(*fname) (where applicable) */
bool lookup_is_dfs(int dfd, struct filename* path, struct dfs_inode** start,
                   const char** dfspath);
bool ulookup_is_dfs(int dfd, const char __user* filename, struct filename** fname,
                    struct dfs_inode** start, const char** dfspath);
#endif /* _LINUX_DENSEFS_H */
