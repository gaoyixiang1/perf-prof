#ifndef __BPF_LSOF_H
#define __BPF_LSOF_H
#define S_IFMT     0170000
#define S_IFREG    0100000
#define S_IFCHR    0020000
#define S_IFDIR    0040000
#define S_IFLNK    0120000
#define S_IFBLK    0060000
#define S_IFIFO    0010000
#define S_IFSOCK   0140000
#define S_IFANON 0xF000  
#define S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)	(((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)	(((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)	(((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m)	(((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m)	(((m) & S_IFMT) == S_IFSOCK)
#define MAX_PATH_DEPTH 16


#define ANON_INODE_FS_MAGIC	0x09041934
#define TCP_ESTABLISHED 1
#define TCP_LISTEN      10

typedef unsigned short		umode_t;
struct file_info {
    __u32 pid;
    __u32 uid;
    int fd;
    unsigned short ftype;
    unsigned int major;
    unsigned int minor;
    unsigned long long size_or_off;
    unsigned int inode;
    char comm[16];
    char name[256];
    __u16 family;
    __u16 sock_type;
    __u8  sk_state;
    __u16 port;
    __u8 protocol;
};

#endif