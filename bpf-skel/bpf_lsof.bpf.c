#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_lsof.h"

#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10
const volatile int target_pid = 0;
const volatile int target_port = 0;
char _license[] SEC("license") = "GPL";
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct file_info);
} file_info_map SEC(".maps");

SEC("iter/task_file")
int dump_task_file(struct bpf_iter__task_file *ctx)
{
    struct file_info *info;
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *task = ctx->task;
    struct file *file = ctx->file;
    __u32 zero = 0;

    if (!task || !file || !seq)
        return 0;

    info = bpf_map_lookup_elem(&file_info_map, &zero);
    if (!info)
        return 0;

    if (target_pid && task->pid != target_pid)
        return 0;

    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry)
        return 0;

    info->pid = task->pid;
    bpf_probe_read_kernel_str(info->comm, sizeof(info->comm), task->comm);
    info->fd = ctx->fd;

    const struct cred *cred = BPF_CORE_READ(task, cred);
    info->uid = cred ? BPF_CORE_READ(cred, uid.val) : 0;

    info->ftype = BPF_CORE_READ(file, f_inode, i_mode) & S_IFMT;

    info->inode = BPF_CORE_READ(dentry, d_inode, i_ino);

    struct super_block *sb = BPF_CORE_READ(dentry, d_inode, i_sb);
    if (sb)
    {
        __u32 magic = BPF_CORE_READ(sb, s_magic);
        if (magic == ANON_INODE_FS_MAGIC)
        {
            info->ftype = S_IFANON;
            info->major = 0;
            info->minor = 15;
        }
    }
    if (target_port != 0 && info->ftype != S_IFSOCK) {
            return 0;
        }
    if (info->ftype == S_IFSOCK)
    {
        struct socket *socket_ptr = NULL;
        bpf_probe_read_kernel(&socket_ptr, sizeof(socket_ptr), &file->private_data);
        if (socket_ptr)
        {
            struct sock *sk_ptr = NULL;
            bpf_probe_read_kernel(&sk_ptr, sizeof(sk_ptr), &socket_ptr->sk);
            if (sk_ptr)
            {
                __u16 family = 0;
                bpf_probe_read_kernel(&family, sizeof(family), &sk_ptr->__sk_common.skc_family);
                info->family = family;
                 if ((info->family != AF_INET && info->family != AF_INET6&&target_port))
                    return 0; 

                __u16 port = 0;
                bpf_probe_read_kernel(&port, sizeof(port), &sk_ptr->__sk_common.skc_num);
                info->port = port;
                 if (target_port&&info->port != target_port)
                     return 0; 
                

                __u8 state = 0;
                bpf_probe_read_kernel(&state, sizeof(state), &sk_ptr->__sk_common.skc_state);
                info->sk_state = state;

                int sock_type = 0;
                bpf_probe_read_kernel(&sock_type, sizeof(sock_type), &socket_ptr->type);
                info->sock_type = sock_type;

                __u8 protocol = 0;
                bpf_probe_read_kernel(&protocol, sizeof(protocol), &sk_ptr->sk_protocol);
                info->protocol = protocol;
            }
        }
    }
    else
    {
        info->family = 0;
        info->sock_type = 0;
        info->sk_state = 0;
        info->port = 0;
        info->protocol = 0;
    }

    __u32 dev = 0;
    if (info->ftype == S_IFCHR || info->ftype == S_IFBLK)
    {
        dev = BPF_CORE_READ(dentry, d_inode, i_rdev);
    }
    else
    {
        struct super_block *sb = BPF_CORE_READ(dentry, d_inode, i_sb);
        dev = sb ? BPF_CORE_READ(sb, s_dev) : 0;
    }
    unsigned int major = (dev >> 20) & 0xfff;
    unsigned int minor = dev & 0xfffff;
    info->major = major;
    info->minor = minor;
    unsigned long long size_or_off = 0;
    if (info->ftype == S_IFREG)
    {
        size_or_off = BPF_CORE_READ(file, f_pos);
    }
    else
    {
        size_or_off = BPF_CORE_READ(file, f_pos);
    }
    info->size_or_off = size_or_off;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, info, sizeof(*info));
    return 0;
}