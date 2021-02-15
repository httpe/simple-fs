#ifndef FILE_SYSTEM_H
#define FILE_SYSTEM_H

#include <stdint.h>

#include "block_io.h"

#include "time.h"

// Mimic Linux stat.h
typedef struct fs_stat {
    uint64_t nlink;		/* Link count.  */
    uint32_t mode;		/* File mode.  */
    uint64_t size;		/* Size of file, in bytes.  */
    uint64_t blocks;	/* Number 512-byte blocks allocated. */
    date_time mtime;	/* Time of last modification.  */
    date_time ctime;	/* Time of last status change.  */
} fs_stat;

// Mimic FUSE struct fuse_file_info
typedef struct fs_file_info {
	/** Open flags.	 Available in open() and release() */
	int32_t flags;
	/** File handle id.  May be filled in by filesystem in create,
	 * open, and opendir().  Available in most other file operations on the
	 * same file handle. */
	uint64_t fh;
} fs_file_info;

// Abstraction of FUSE fuse_fill_dir_t
typedef struct fs_dir_filler_info fs_dir_filler_info; // Opaque struct, definition differ in FUSE vs simple-OS 
typedef int (*fs_dir_filler) (fs_dir_filler_info*, const char *name, const struct fs_stat *); // definition differ in FUSE vs simple-OS 

struct fs_mount_point; // Declaring below

// Mimic FUSE struct fuse_operations
typedef struct file_system_operations {
    int (*getattr) (struct fs_mount_point* mount_point, const char * path, struct fs_stat *, struct fs_file_info *);
    int (*mknod) (struct fs_mount_point* mount_point, const char * path, uint32_t mode);
    int (*mkdir) (struct fs_mount_point* mount_point, const char * path, uint32_t mode);
    int (*unlink) (struct fs_mount_point* mount_point, const char * path);
    int (*rmdir) (struct fs_mount_point* mount_point, const char * path);
    int (*rename) (struct fs_mount_point* mount_point, const char * from, const char * to, unsigned int flags);
    int (*truncate) (struct fs_mount_point* mount_point, const char * path, int64_t size, struct fs_file_info *fi);
    int (*open) (struct fs_mount_point* mount_point, const char * path, struct fs_file_info *);
    int (*read) (struct fs_mount_point* mount_point, const char * path, char *buf, uint64_t size, int64_t offset, struct fs_file_info *);
	int (*write) (struct fs_mount_point* mount_point, const char * path, const char *buf, uint64_t size, int64_t offset, struct fs_file_info *);
	int (*release) (struct fs_mount_point* mount_point, const char * path, struct fs_file_info *);
	int (*readdir) (struct fs_mount_point* mount_point, const char * path, struct fs_dir_filler_info*, fs_dir_filler);
} file_system_operations_t;

typedef struct fs_mount_option {
    uint32_t flag;
} fs_mount_option;

enum file_system_type {
    FILE_SYSTEM_FAT_32
};

struct fs_mount_point;
struct file_system {
    enum file_system_type type;
    void* fs_global_meta;
    int (*mount) (struct fs_mount_point* mount_point);
};
typedef struct fs_mount_point {
    struct file_system* fs;
    block_storage_t* storage;
    char* mount_target;
    void* fs_option; 
    struct fs_mount_option mount_option;

    void* fs_meta; // File system internal data structure
    struct file_system_operations operations;
} fs_mount_point;



// int32_t fs_mount(block_storage_t* storage, const char* target, enum file_system_type file_system_type, 
//             struct fs_mount_option option, const void* fs_option, fs_mount_point* mount_point);


#endif