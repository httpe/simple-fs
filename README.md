# Simple-FS

This is the file system part of the [Simple-OS project](https://github.com/httpe/simple-os). We will implement several common file systems using FUSE interface and ultimately merge the code into Simple-OS kernel.

## Dependencies

1. [GCC](https://gcc.gnu.org/): The project is tested to be compiled by GCC.

1. [FUSE](https://en.wikipedia.org/wiki/Filesystem_in_Userspace): We use FUSE to help us implementing the file system (see `Implementing File System` section). For linux, we use [libfuse](https://github.com/libfuse/libfuse). For macOS, the library is [macFUSE](https://osxfuse.github.io/). We test compile in Ubuntu 20.04 LTS against package `libfuse3-dev` and `fuse3`.

## Implemented File System

We have implemented two file systems right now:

1. A hand-crafted (very simple) file system: It is the simplest file system that we can design in order to implement most common FUSE interface such as listing dir, creating, reading and writing files.
    - If you follow the `Build & Run` section below, the binary `simple_fs_block` generated is the FUSE driver for this file system.
    - The basic file system layout is as follow:
        1. There are 32 16 bytes file entries at the beginning of the disk.
            1. 12 bytes ASCII file name
            1. 2 bytes of attributes, currently we only use 1 bit of it to indicated whether the entry is representing a directory or a file
            1. 2 bytes of file size
        1. 32 data blocks for each of the file entries above
            1. The data blocks are fixed length, 512 bytes each
    - Please see `simple_fs.h` for the design in detail.
    - There are two implementation of the file system, `simple_fs.c` and `simple_fs_block.c`. They are mostly identical, except for `simple_fs.c` will call host OS's I/O functions directly to read/write disk image while `simple_fs_block.c` delegate the I/O to our `block_io.h` interface. Please see `The Plan on Implementing File System` for more details.

1. A [FAT-32](https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system) file system: It is one of the main goal of this project. 
    - If you follow the `Build & Run` section below, the binary `fat` generated is the FUSE driver for this file system.
    - The current implementation is read-only, further progress are expected.
    - Our goal is to implement most FAT-32 features, including writing of course, but excluding:
        - USC-2 unicode support: We will replace any non US-ASCII (code point > 127) characters to '?', since implementing unicode support is hard and not the main purpose of this project.
        - Support for maximum compatibility: We will only support the clean and standard version of FAT-32 (as documented on the Wikipedia page), without considering to make it working on older FAT file system, such as FAT-12 and FAT-16 or non-standard/corrupted file system.

## Build & Run

### Build
You can built the source code by:

```bash
make all
```

Two programs `simple_fs_block` and `fat` shall be generated.

### Run

To mount our **hand-crafted file system**:

```bash
mkdir -p mnt
simple_fs_block -s -d mnt
```

All file system changes will be written to `simple_fs_image.bin`.

To inspect the disk image:

```bash
hd simple_fs_image.bin
```

Note that the file system will reformat the image every time when initializing.

To mount the **FAT-32 file system**:

```bash
mkdir -p mnt
fat -s -d mnt --image_path=testfs.fat
```

One possible FAT-32 disk image for testing can be found at [FAT32-FS-Driver/testfs.fat.tar](https://github.com/aroulin/FAT32-FS-Driver/blob/master/testfs.fat.tar), from one of our reference project.

## The Plan on Implementing File System

File system is a rather complicated component of the operating system, so we will split it out as an individual project and we will break it into multiple smaller stages to make the effort more organized. The core idea is to use FUSE as a intermediary such that we can operate on our file system in our host operating system. Also FUSE provides us a fairly standardized disk driver interface so we know what are the components to be implemented.

1. Build a very simple [FUSE](https://wiki.osdev.org/FUSE) ([libfuse](https://github.com/libfuse/libfuse)) file system fulfilling the following requirements:
    - Implement basic FUSE interface such as open, close, read, write, dir listing, attribute retrieval, file/dir creation and file/dir deletion
    - The data are read from and written to a single binary file (i.e. disk image)
    - Reference
        - [Less-Simple-Yet-Stupid-Filesystem](https://maastaar.net/fuse/linux/filesystem/c/2019/09/28/writing-less-simple-yet-stupid-filesystem-using-FUSE-in-C/)
        - libfuse [Pass through example](https://github.com/libfuse/libfuse/blob/master/example/passthrough.c)
    - **Done**

1. Design a set of block I/O API to read/write sectors, query meta disk data (like disk size) etc. Delegate all read/write to the disk image in the last step by the block I/O API. For FUSE, we implement the API as host system system calls/standard C library calls.
    - **Done**

1. Implement the actual targeted file system, like FAT32 ([OsDev]((https://wiki.osdev.org/FAT32)), [Wiki](https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system)) or [Ext2](https://wiki.osdev.org/Ext2) in FUSE, through the block I/O API.

1. Implement the block I/O API in our system through [ATA (PIO)](https://wiki.osdev.org/ATA_PIO_Mode) operations.

1. (Optional) Implement block level I/O buffer cache. (Ref [Xv6/bio.c]( https://github.com/mit-pdos/xv6-public/blob/master/bio.c))

1. Design the system call for file I/O and file descriptor management (Ref [Xv6/sysfile.c](https://github.com/mit-pdos/xv6-public/blob/master/sysfile.c) and [Xv6/file.c](https://github.com/mit-pdos/xv6-public/blob/master/file.c))

1. Port the FUSE file system to our kernel (and bootloader). The final call stack shall looks like: libc function call (e.g. open()) -> kernel system call -> Simple-FS driver (e.g. .open in fuse_operations) -> ATA driver. (Ref [Xv6/fs.c](https://github.com/mit-pdos/xv6-public/blob/master/fs.c))

1. Use FUSE to mount and fill the disk image with kernel files, append the filled image after the bootloader sectors, and record it as a partition in MBR partition table. Potentially implement a formatter (Ref [Xv6/mkfs.c](https://github.com/mit-pdos/xv6-public/blob/master/mkfs.c))

1. The kernel now resides in the desired file system, the bootloader can load it from there, and the kernel understands the file system and have full control over it.
