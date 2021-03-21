#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "vfs.h"
#include "make_fs.h"

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
    block_storage* storage = get_block_storage(0);

    if(make_fs) {
        printf("Formatting file system...\n");
        int32_t res = fat32_make_fs(storage, make_fs_bootloader_path);
        if(res < 0) {
            printf("Failed to format the file system: %d\n", res);
            exit(1);
        }
    }

    assert(init_vfs()==0);

    // fs_mount_option mount_option = {0};
    // fs_mount_point* mp = NULL;
    // res = fs_mount(storage, "/", FILE_SYSTEM_FAT_32, mount_option, NULL, &mp);
    // assert(res == 0);

    // char buf_in[512] = {0}, buf_out[512] = {0};
    // strcpy(buf_in, "Hello User I/O World!");
    // int fd = fs_open("/RAND.OM", 0);
    // assert(fd == 0);

    // int read = fs_read(fd, buf_out, 10);
    // assert(read == 10);
    // printf("%s", buf_out);
    // int close_res = fs_close(fd);
    // assert(close_res == 0);

    // fd = fs_open("/RAND.OM", 0);
    // assert(fd == 0);
    // int written = fs_write(fd, buf_in, strlen(buf_in) + 1);
    // assert(written == strlen(buf_in) + 1);
    // int seek_res = fs_seek(fd, -(strlen(buf_in) + 1), SEEK_WHENCE_CUR);
    // assert(seek_res == 0);
    // read = fs_read(fd, buf_out, strlen(buf_in) + 1);
    // assert(read == strlen(buf_in) + 1);
    // assert(strcmp(buf_out, buf_in) == 0);
    // close_res = fs_close(fd);
    // assert(close_res == 0);

    // return 0;


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

    // test open/read/write/seek/close
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
    int seek_res = fs_seek(fd, -5, SEEK_WHENCE_END);
    assert(seek_res == 0);
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
