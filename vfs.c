#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "block_io.h"
#include "fat.h"
#include "make_fs.h"
#include "file_system.h"
#include "file_descriptor.h"
#include "errno.h"

#define SEEK_SET 1
#define SEEK_CUR 2
#define SEEK_END 3

#define N_MOUNT_POINT 16

uint32_t next_mount_point_id = 1;

fs_mount_point mount_points[N_MOUNT_POINT];
file_system fs[N_FILE_SYSTEM_TYPES];
const char* root_path = "/";

// Global (kernel) file table for all opened files
struct {
  file file[N_FILE_STRUCTURE];
} file_table;

proc current_process;

proc* curr_proc()
{
    return &current_process;
}

fs_mount_point* find_mount_point(const char* path, const char**remaining_path)
{
    // Return the longest prefix matched mount point to allow mount point inside of mounted folder
    int max_match_mount_point_id = -1;
    int max_match_len = 0;
    *remaining_path = NULL;
    if(*path != '/') {
        // Do not support relative path, yet
        return NULL;
    }
    for(int i=0;i<N_MOUNT_POINT;i++) {
        if(mount_points[i].mount_target != NULL) {
            int match_len = 0;
            const char* p = path;
            const char* m = mount_points[i].mount_target;
            if(strcmp(m, root_path) == 0) {
                // mount = "/"
                if(max_match_len < 1) {
                    max_match_mount_point_id = i;
                    max_match_len = 1;
                    *remaining_path = p;
                }
                continue;
            }
            while(*p != 0 && *m != 0 && *p == *m) {
                p++;
                m++;
                match_len++;
            }
            if(*p == 0 && *m == 0) {
                // path = "/abc", mount = "/abc"
                *remaining_path = root_path;
                return &mount_points[i];
            }
            if(*p == '/' && *m == 0) {
                // path = "/abc/xyz", mount = "/abc"
                assert(max_match_len != match_len);
                if(max_match_len < match_len) {
                    max_match_mount_point_id = i;
                    max_match_len = match_len;
                    *remaining_path = p;
                }
            }
        }
    }
    if(max_match_mount_point_id == -1) {
        return NULL;
    } else {
        return &mount_points[max_match_mount_point_id];
    }
}


int32_t fs_mount(block_storage_t* storage, const char* target, enum file_system_type file_system_type, 
            fs_mount_option option, void* fs_option, fs_mount_point** mount_point)
{
    int i;
    for(i=0; i<N_FILE_SYSTEM_TYPES; i++) {
        if(fs[i].type == file_system_type && fs[i].status == FS_STATUS_READY) {
            break;
        }
    }
    if(i == N_FILE_SYSTEM_TYPES) {
        // file system not found
        return -1;
    }
    int j;
    for(j=0;j<N_MOUNT_POINT;j++) {
        if(mount_points[j].mount_target != NULL) {
            if(strcmp(mount_points[j].mount_target, target) == 0) {
                // target already mounted
                return -1;
            }
        }
    }
    for(j=0;j<N_MOUNT_POINT;j++) {
        if(mount_points[j].mount_target == NULL) {
            mount_points[j] = (fs_mount_point) {
                .id = next_mount_point_id++,
                .fs = &fs[i],
                .storage = storage,
                .mount_target=strdup(target), 
                .mount_option=option, 
                .fs_option = fs_option
            };
            int res = fs[i].mount(&mount_points[j]);
            if(res < 0) {
                free(mount_points[j].mount_target);
                memset(&mount_points[j], 0, sizeof(mount_points[j]));
                *mount_point = NULL;
                return res;
            }
            *mount_point = &mount_points[j];
            return 0;
        }
    }
    // No mount point available
    return -1;
}

int32_t fs_unmount(const char* mount_root)
{
    const char* remaining_path = NULL;
    fs_mount_point* mp = find_mount_point(mount_root, &remaining_path);
    if(mp == NULL || strcmp(remaining_path, root_path) != 0) {
        return -ENXIO;
    }
    int32_t res = mp->fs->unmount(mp);
    if(res < 0) {
        return res;
    }
    memset(mp, 0, sizeof(*mp));
    return 0;
}

int64_t fs_getattr(const char * path, struct fs_stat * stat)
{
    const char* remaining_path = NULL;
    fs_mount_point* mp = find_mount_point(path, &remaining_path);
    if(mp == NULL) {
        return -ENXIO;
    }
    if(mp->operations.getattr == NULL) {
        // if file system does not support this operation
        return -EPERM;
    }

    int res = mp->operations.getattr(mp, remaining_path, stat, NULL);
    
    return res;
}

int64_t fs_mknod(const char * path, uint32_t mode)
{
    const char* remaining_path = NULL;
    fs_mount_point* mp = find_mount_point(path, &remaining_path);
    if(mp == NULL) {
        return -ENXIO;
    }
    if(mp->operations.mknod == NULL) {
        // if file system does not support this operation
        return -EPERM;
    }

    int res = mp->operations.mknod(mp, remaining_path, mode);
    
    return res;
}

int64_t fs_mkdir(const char * path, uint32_t mode)
{
    const char* remaining_path = NULL;
    fs_mount_point* mp = find_mount_point(path, &remaining_path);
    if(mp == NULL) {
        return -ENXIO;
    }
    if(mp->operations.mkdir == NULL) {
        // if file system does not support this operation
        return -EPERM;
    }

    int res = mp->operations.mkdir(mp, remaining_path, mode);
    
    return res;
}

int64_t fs_rmdir(const char * path)
{
    const char* remaining_path = NULL;
    fs_mount_point* mp = find_mount_point(path, &remaining_path);
    if(mp == NULL) {
        return -ENXIO;
    }
    if(mp->operations.rmdir == NULL) {
        // if file system does not support this operation
        return -EPERM;
    }

    int res = mp->operations.rmdir(mp, remaining_path);
    
    return res;
}

int64_t fs_unlink(const char * path)
{
    const char* remaining_path = NULL;
    fs_mount_point* mp = find_mount_point(path, &remaining_path);
    if(mp == NULL) {
        return -ENXIO;
    }
    if(mp->operations.unlink == NULL) {
        // if file system does not support this operation
        return -EPERM;
    }

    int res = mp->operations.unlink(mp, remaining_path);
    
    return res;
}

int64_t fs_truncate(const char * path, int64_t size)
{
    const char* remaining_path = NULL;
    fs_mount_point* mp = find_mount_point(path, &remaining_path);
    if(mp == NULL) {
        return -ENXIO;
    }
    if(mp->operations.truncate == NULL) {
        // if file system does not support this operation
        return -EPERM;
    }

    int res = mp->operations.truncate(mp, remaining_path, size, NULL);
    
    return res;
}

int64_t fs_rename(const char * from, const char* to, uint32_t flags)
{
    const char* remaining_path_from = NULL;
    fs_mount_point* mp_from = find_mount_point(from, &remaining_path_from);
    if(mp_from == NULL) {
        return -ENXIO;
    }
    if(mp_from->operations.rename == NULL) {
        // if file system does not support this operation
        return -EPERM;
    }

    const char* remaining_path_to = NULL;
    fs_mount_point* mp_to = find_mount_point(to, &remaining_path_to);
    if(mp_to == NULL) {
        return -ENXIO;
    }
    if(mp_to != mp_from) {
        // cannot rename (move) between different mount points
        return -EPERM;
    }

    int res = mp_from->operations.rename(mp_from, remaining_path_from, remaining_path_to, flags);
    
    return res;
}

int32_t fs_open(const char * path, int32_t flags)
{
    const char* remaining_path = NULL;
    fs_mount_point* mp = find_mount_point(path, &remaining_path);
    if(mp == NULL) {
        return -ENXIO;
    }
    if(mp->operations.open == NULL) {
        // if file system does not support this operation
        return -EPERM;
    }

    // allocate kernel file structure
    file* f = NULL; 
    for(int i=0;i<N_FILE_STRUCTURE;i++) {
        if(file_table.file[i].ref == 0) {
            f = &file_table.file[i];
            break;
        }
    }
    if(f == NULL) {
        // No available file structure cache
        return -ENFILE;
    }

    // file descriptor is the index into (one process's) file_table
    proc* p = curr_proc();
    int fd;
    for(fd=0; fd<N_FILE_DESCRIPTOR_PER_PROCESS;fd++) {
        if(p->opended_files[fd] == NULL) {
            break;
        }
    }
    if(fd == N_FILE_DESCRIPTOR_PER_PROCESS) {
        // too many opended files
        return -EMFILE;
    }

    fs_file_info fi = {.flags = flags, .fh=0};
    int32_t res = mp->operations.open(mp, remaining_path, &fi);
    if(res < 0) {
        return res;
    }
    *f = (file) {
        .inum = fi.fh, // file system's internal inode number / file handler number
        .open_flags = flags,
        .mount_point = mp,
        .offset = 0,
        .ref = 1,
        .path = strdup(remaining_path), //storing path relative to the mount point
        .readable = !(flags & O_WRONLY),
        .writable = (flags & O_WRONLY) || (flags & O_RDWR)
    };
    p->opended_files[fd] = f;

    // Return file descriptor
    return fd;
}

struct fs_dir_filler_info {
    void* buf;
    uint32_t buf_size;
    uint32_t entry_written;
};

int dir_filler(fs_dir_filler_info* filler_info, const char *name, const struct fs_stat *st)
{
    (void) st;

    if((filler_info->entry_written + 1)*sizeof(fs_dirent) > filler_info->buf_size) {
        // buffer full
        return 1;
    } else {
        uint len = strlen(name);
        if(len > FS_MAX_FILENAME_LEN) {
            len = FS_MAX_FILENAME_LEN;
        }
        fs_dirent* dirent = (fs_dirent*) (filler_info->buf + filler_info->entry_written * sizeof(fs_dirent));
        memmove(dirent->name, name, len+1);
        filler_info->entry_written++;
        return 0;
    }
}

int32_t fs_readdir(const char * path, int64_t entry_offset, fs_dirent* buf, uint32_t buf_size) 
{
    const char* remaining_path = NULL;
    fs_mount_point* mp = find_mount_point(path, &remaining_path);
    if(mp == NULL) {
        return -ENXIO;
    }
    if(mp->operations.readdir == NULL) {
        // if file system does not support this operation
        return -EPERM;
    }
    struct fs_dir_filler_info filler_info = {.buf = buf, .buf_size = buf_size, .entry_written = 0};
    int res = mp->operations.readdir(mp, remaining_path, entry_offset, &filler_info, dir_filler);
    if(res < 0) {
        return res;
    }

    return filler_info.entry_written;
}

file* fd2file(int32_t fd)
{
    proc* p = curr_proc();
    if(fd < 0 || fd >= N_FILE_STRUCTURE || p->opended_files[fd] == NULL || p->opended_files[fd]->ref == 0) {
        return NULL;
    }
    file* f = p->opended_files[fd];
    return f;
}

int32_t fs_close(int32_t fd)
{
    proc* p = curr_proc();
    file* f = fd2file(fd);
    if(f == NULL) {
        return -EBADF;
    }
    if(f->mount_point->operations.release == NULL) {
        // if file system does not support this operation
        return -EPERM;
    }

    struct fs_file_info fi = {.flags = f->open_flags, .fh=f->inum};
    int32_t res = f->mount_point->operations.release(f->mount_point, f->path, &fi);
    if(res < 0) {
        return res;
    }

    p->opended_files[fd]->ref--;
    if(p->opended_files[fd]->ref == 0) {
        free(p->opended_files[fd]->path);
        memset(f, 0, sizeof(*f));
    }

    p->opended_files[fd] = NULL;
    
    return 0;
}

int64_t fs_read(int32_t fd, void *buf, uint32_t size)
{
    file* f = fd2file(fd);
    if(f == NULL) {
        return -EBADF;
    }
    if(f->mount_point->operations.read == NULL) {
        // if file system does not support this operation
        return -EPERM;
    }

    struct fs_file_info fi = {.flags = f->open_flags, .fh=f->inum};
    int64_t res = f->mount_point->operations.read(f->mount_point, f->path, buf, size, f->offset, &fi);
    if(res < 0) {
        return res;
    }
    f->offset += res;
    
    return res;
}

int64_t fs_lseek(int32_t fd, int64_t offset, int32_t whence)
{
    file* f = fd2file(fd);
    if(f == NULL) {
        return -EBADF;
    }

    if(whence == SEEK_CUR) {
        f->offset += offset;
    } else if(whence == SEEK_SET) {
        f->offset = offset;
    } else if(whence == SEEK_END) {
        fs_stat st = {0};
        if(f->mount_point->operations.getattr == NULL) {
            // if file system does not support this operation
            return -EPERM;
        }
        int res = f->mount_point->operations.getattr(f->mount_point, f->path, &st, NULL);
        if(res<0){
            return res;
        }
        f->offset = st.size + offset;
    } else {
        return -EPERM;
    }

    return 0;
    
}

int64_t fs_write(int32_t fd, void *buf, uint32_t size)
{
    file* f = fd2file(fd);
    if(f == NULL) {
        return -EBADF;
    }
    if(f->mount_point->operations.write == NULL) {
        // if file system does not support this operation
        return -EPERM;
    }

    struct fs_file_info fi = {.flags = f->open_flags, .fh=f->inum};
    int64_t res = f->mount_point->operations.write(f->mount_point, f->path, buf, size, f->offset, &fi);
    if(res < 0) {
        return res;
    }
    f->offset += res;
    
    return res;
}

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;

    const char* image_path = "vfs_image.bin";
    int make_fs = 1;
    const char* make_fs_bootloader_path = NULL;

    int res = initialize_block_storage(image_path);
    if(res < 0) {
        printf("Disk image failed to initialize: %d\n", res);
        exit(1);
    }

    // Assume to use first block storage
    block_storage_t* storage = get_block_storage(0);

    if(make_fs) {
        printf("Formatting file system...\n");
        int32_t res = fat32_make_fs(storage, make_fs_bootloader_path);
        if(res < 0) {
            printf("Failed to format the file system: %d\n", res);
            exit(1);
        }
    }

    // initialize all supported file systems
    fs[0] = (struct file_system) {.type = FILE_SYSTEM_FAT_32};
    res = fat32_init(&fs[0]);
    assert(res == 0);

    fs_mount_option mount_option = {0};
    fs_mount_point* mp = NULL;
    res = fs_mount(storage, "/home", FILE_SYSTEM_FAT_32, mount_option, NULL, &mp);
    assert(res == 0);

    // try resolving mount point
    const char* rem_path = NULL;
    fs_mount_point* mp1 = find_mount_point("/home/my_file", &rem_path);
    assert(mp1 == mp);
    assert(strcmp("/my_file", rem_path) == 0);

    // test mknod/mkdir
    int res_mkdir = fs_mkdir("/home/my_dir", 0);
    assert(res_mkdir == 0);
    int res_mknod = fs_mknod("/home/my_dir/my_file", 0);
    assert(res_mknod == 0);

    // test open/read/write/lseek/close
    char buf_in[512], buf_out[512];
    strcpy(buf_in, "Hello World!");
    int fd = fs_open("/home/my_dir/my_file", 0);
    assert(fd == 0);
    int written = fs_write(fd, buf_in, strlen(buf_in) + 1);
    assert(written == 13);
    int close_res = fs_close(fd);
    assert(close_res == 0);
    fd = fs_open("/home/my_dir/my_file", 0);
    assert(fd == 0);
    int read = fs_read(fd, buf_out, 2);
    assert(read == 2);
    read = fs_read(fd, buf_out + 2, 100);
    assert(read == 11);
    assert(strcmp(buf_out, buf_in) == 0);
    int lseek_res = fs_lseek(fd, -5, SEEK_END);
    assert(lseek_res == 0);
    read = fs_read(fd, buf_out, 100);
    assert(read == 5);
    assert(strcmp(buf_out, buf_in + strlen(buf_in) - 5 + 1) == 0);
    close_res = fs_close(fd);
    assert(close_res == 0);

    // test getattr
    fs_stat stat = {0};
    int res_getattr = fs_getattr("/home/my_dir/my_file", &stat);
    assert(res_getattr == 0);
    assert(stat.size == 13);

    // test truncate
    int res_truncate = fs_truncate("/home/my_dir/my_file", 100);
    assert(res_truncate == 0);
    res_getattr = fs_getattr("/home/my_dir/my_file", &stat);
    assert(stat.size == 100);
    res_truncate = fs_truncate("/home/my_dir/my_file", 0);
    assert(res_truncate == 0);
    res_getattr = fs_getattr("/home/my_dir/my_file", &stat);
    assert(res_getattr == 0);
    assert(stat.size == 0);

    // test readdir
    fs_dirent dir_buf[10];
    int dirent_read = fs_readdir("/home", 0, dir_buf, sizeof(fs_dirent)*10);
    assert(dirent_read == 1);
    assert(strcmp(dir_buf[0].name, "my_dir") == 0);
    dirent_read = fs_readdir("/home/my_dir", 0, dir_buf, sizeof(fs_dirent)*10);
    assert(dirent_read == 3);
    assert(strcmp(dir_buf[0].name, ".") == 0);
    assert(strcmp(dir_buf[1].name, "..") == 0);
    assert(strcmp(dir_buf[2].name, "my_file") == 0);

    // test rename
    int res_rename = fs_rename("/home/my_dir/my_file", "/home/my_dir/my_new_file", 0);
    assert(res_rename == 0);
    dirent_read = fs_readdir("/home/my_dir", 0, dir_buf, sizeof(fs_dirent)*10);
    assert(dirent_read == 3);
    assert(strcmp(dir_buf[0].name, ".") == 0);
    assert(strcmp(dir_buf[1].name, "..") == 0);
    assert(strcmp(dir_buf[2].name, "my_new_file") == 0);

    // test unlink/rmdir
    int res_unlink = fs_unlink("/home/my_dir/my_new_file");
    assert(res_unlink == 0);
    dirent_read = fs_readdir("/home/my_dir", 0, dir_buf, sizeof(fs_dirent)*10);
    assert(dirent_read == 2);
    int res_rmdir = fs_rmdir("/home/my_dir");
    assert(res_rmdir == 0);
    dirent_read = fs_readdir("/home", 0, dir_buf, sizeof(fs_dirent)*10);
    assert(dirent_read == 0);

    //test unmount
    int unmount_res = fs_unmount("/home");
    assert(unmount_res == 0);
    fs_mount_point* mp_end = find_mount_point("/home/my_file", &rem_path);
    assert(mp_end == NULL);

	return 0;
}
