#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <pthread.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <pwd.h>
#include "monitor.h"
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "bpf-skel/bpf_lsof.skel.h"
#include "bpf-skel/bpf_lsof.h"

struct bpfiter_ctx
{
    struct bpf_lsof_bpf *skel;
    struct bpf_link *link;
    struct perf_buffer *pb;
    int iter_fd;
    FILE *output;
    bool print_header;
    pthread_t iter_thread;
    volatile bool stop;
    struct env *env;
};
struct task_details
{
    char user_str[32];
    char ruser_str[32];
    char comm_str[512];
    char time_str[32];
};
static const char *file_type_str(unsigned short ftype)
{
    switch (ftype)
    {
    case S_IFREG:
        return "REG";
    case S_IFCHR:
        return "CHR";
    case S_IFDIR:
        return "DIR";
    case S_IFLNK:
        return "LNK";
    case S_IFBLK:
        return "BLK";
    case S_IFIFO:
        return "FIFO";
    case S_IFSOCK:
        return "SOCK";
    case S_IFANON:
        return "a_inode";
    default:
        return "unknown";
    }
}

static const char *sock_proto_str(unsigned short family, unsigned short protocol)
{
    if (family == AF_INET || family == AF_INET6)
    {
        if (protocol == IPPROTO_TCP)
            return "TCP";
        else if (protocol == IPPROTO_UDP)
            return "UDP";
        else
            return "INET";
    }
    else if (family == AF_UNIX)
    {
        return "unix";
    }
    return "SOCK";
}

static void handle_events(void *ctx, int cpu, void *data, __u32 size)
{
    struct bpfiter_ctx *bpf_ctx = ctx;
    const struct file_info *info = data;
    struct passwd *pw;
    char user_str[32] = "-";
    char name_buf[256] = "-";
    char size_buf[32] = "";
    char port_buf[16] = "-";
    char state_buf[16] = "-";
    char type_buf[16] = "-";
    char path_buf[256] = "-";
    char link_path[64];
    size_t link_len = 0;
    FILE *out = bpf_ctx->output ? bpf_ctx->output : stdout;
    struct env *env = bpf_ctx->env;
    
    pw = getpwuid(info->uid);
    if (pw)
    {
        strncpy(user_str, pw->pw_name, sizeof(user_str) - 1);
        user_str[sizeof(user_str) - 1] = '\0';
        if (strlen(user_str) > 8)
        {
            user_str[7] = '+';
            user_str[8] = '\0';
        }
    }

    // 类型
    if (info->ftype == S_IFSOCK)
    {
        strncpy(type_buf, sock_proto_str(info->family, info->protocol), sizeof(type_buf) - 1);
        type_buf[sizeof(type_buf) - 1] = '\0';
    }
    else
    {
        strncpy(type_buf, file_type_str(info->ftype), sizeof(type_buf) - 1);
        type_buf[sizeof(type_buf) - 1] = '\0';
    }

    // 设备号和大小
    if (info->ftype == S_IFANON)
    {
        snprintf(size_buf, sizeof(size_buf), "0");
    }
    else if (strcmp(type_buf, "unknown") == 0)
    {
        snprintf(size_buf, sizeof(size_buf), " ");
    }
    else
    {
        snprintf(size_buf, sizeof(size_buf), "%llu", info->size_or_off);
    }

    if (env->path||env->grep||env->unix_file)
    {
        // 路径
        snprintf(link_path, sizeof(link_path), "/proc/%d/task/%d/fd/%d",
                 info->pid, info->pid, info->fd);
        link_len = readlink(link_path, path_buf, sizeof(path_buf) - 1);
        if (link_len >= 0)
        {
            path_buf[link_len] = '\0';
        }
        else if (info->name[0])
        {
            strncpy(path_buf, info->name, sizeof(path_buf) - 1);
            path_buf[sizeof(path_buf) - 1] = '\0';
        }
        else
        {
            strcpy(path_buf, "-");
        }
    }

    //path
    if (env && env->path && env->path[0])
    {
        if (strcmp(path_buf, env->path) != 0)
        {
            return; 
        }
    }

    // unix_file
    if (env && env->unix_file)
    {
        if (!(info->ftype == S_IFSOCK && info->family == AF_UNIX))
        {
            return;
        }
    }
    // tcp_listen
    if (env && env->tcp_listen)
    {
        if (!(info->ftype == S_IFSOCK &&
              (info->family == AF_INET || info->family == AF_INET6) &&
              info->protocol == IPPROTO_TCP &&
              info->sk_state == TCP_LISTEN))
        {
            return;
        }
    }
    if (env && env->grep && env->grep[0])
    {
        if (strstr(path_buf, env->grep) == NULL)
        {
            return;
        }
    }
    // port state
    if (info->ftype == S_IFSOCK)
    {
        if (info->family == AF_INET || info->family == AF_INET6)
        {
            snprintf(port_buf, sizeof(port_buf), "%u", info->port);
            if (info->sk_state == TCP_LISTEN)
                strcpy(state_buf, "LISTEN");
            else if (info->sk_state == TCP_ESTABLISHED)
                strcpy(state_buf, "ESTABLISHED");
            else
                strcpy(state_buf, "-");

            snprintf(name_buf, sizeof(name_buf), "%s:%u (%s)",
                     info->family == AF_INET ? "IPv4" : "IPv6", info->port, state_buf);
        }
        else if (info->family == AF_UNIX)
        {
            // unix socket
            strncpy(name_buf, path_buf, sizeof(name_buf) - 1);
            name_buf[sizeof(name_buf) - 1] = '\0';
            strcpy(port_buf, "-");
            strcpy(state_buf, "-");
        }
        else
        {
            strcpy(name_buf, "-");
            strcpy(port_buf, "-");
            strcpy(state_buf, "-");
        }
    }
    else
    {
        strncpy(name_buf, path_buf, sizeof(name_buf) - 1);
        name_buf[sizeof(name_buf) - 1] = '\0';
        strcpy(port_buf, "-");
        strcpy(state_buf, "-");
    }
    if (env->grep)
    {
        if (bpf_ctx->print_header)
        {
            fprintf(out, " %-15s %-8s %-8s %-6s %-8s\n",
                    "COMMAND", "PID", "USER", "FD", "NAME");
            bpf_ctx->print_header = false;
        }
        fprintf(out, "%-15s %-8d %-8s %-6d  %-8s\n",
                info->comm, info->pid, user_str, info->fd,
                name_buf);
    }
    else if (env->port)
    {
       
        if (bpf_ctx->print_header)
        {
            fprintf(out, " %-15s %-8s %-8s  %-10s %-20s %-8s\n",
                    "COMMAND", "PID", "USER", "PORT", "STATE", "NAME");
            bpf_ctx->print_header = false;
        }
        fprintf(out, "%-15s %-8d %-8s  %-10s %-20s %-8s\n",
                info->comm, info->pid, user_str,
                port_buf, state_buf, name_buf);
    }
    else if (env->pidof && env->tcp_listen)
    {
        if (bpf_ctx->print_header)
        {
            fprintf(out, " %-15s %-8s %-8s  %-10s %-8s\n",
                    "COMMAND", "PID", "USER", "SIZE/OFF", "NAME");
            bpf_ctx->print_header = false;
        }
        fprintf(out, "%-15s %-8d %-8s %-8s %-8s\n",
                info->comm, info->pid, user_str, size_buf, name_buf);
    }
    else if (env->pidof)
    {
        if (bpf_ctx->print_header)
        {
            fprintf(out, " %-15s %-8s %-8s %-6s %-8s %-10s %-10s  %-8s\n",
                    "COMMAND", "PID", "USER", "FD", "TYPE", "SIZE/OFF", "NODE", "NAME");
            bpf_ctx->print_header = false;
        }
        fprintf(out, "%-15s %-8d %-8s %-6d %-8s %-10s %-10u %-8s\n",
                info->comm, info->pid, user_str, info->fd,
                type_buf, size_buf, info->inode,
                name_buf);
    }else if(env->tcp_listen){
         if (bpf_ctx->print_header) {
            fprintf(out, " %-15s %-8s %-8s  %-10s %-8s\n",
                    "COMMAND", "PID", "USER", "SIZE/OFF", "NAME");
            bpf_ctx->print_header = false;
        }
        fprintf(out, "%-15s %-8d %-8s %-8s %-8s\n",
                info->comm, info->pid, user_str, size_buf, name_buf);
    }
    else if (env->path)
    {
        if (bpf_ctx->print_header)
        {
            fprintf(out, " %-15s %-8s %-8s  %-10s %-8s\n",
                    "COMMAND", "PID", "USER", "SIZE/OFF", "NAME");
            bpf_ctx->print_header = false;
        }
        fprintf(out, "%-15s %-8d %-8s %-8s %-8s\n",
                info->comm, info->pid, user_str, size_buf, name_buf);
    }
    else
    {
        if (bpf_ctx->print_header)
        {
            fprintf(out, " %-15s %-8s %-8s %-6s %-8s %-10s %-10s %-10s %-20s %-8s\n",
                    "COMMAND", "PID", "USER", "FD", "TYPE", "SIZE/OFF", "NODE", "PORT", "STATE", "NAME");
            bpf_ctx->print_header = false;
        }
        fprintf(out, "%-15s %-8d %-8s %-6d %-8s %-10s %-10u %-10s %-20s %-8s\n",
                info->comm, info->pid, user_str, info->fd,
                type_buf, size_buf, info->inode,
                port_buf, state_buf, name_buf);
    }

    fflush(out);
}

/* clean */
static void cleanup_ctx(struct bpfiter_ctx *ctx)
{
    if (!ctx)
        return;

    if (ctx->pb)
    {
        perf_buffer__free(ctx->pb);
        ctx->pb = NULL;
    }
    if (ctx->output)
    {
        fclose(ctx->output);
        ctx->output = NULL;
    }
    if (ctx->iter_fd >= 0)
    {
        close(ctx->iter_fd);
        ctx->iter_fd = -1;
    }
    if (ctx->link)
    {
        bpf_link__destroy(ctx->link);
        ctx->link = NULL;
    }
    if (ctx->skel)
    {
        bpf_lsof_bpf__destroy(ctx->skel);
        ctx->skel = NULL;
    }
    free(ctx);
}

//bpf
static int bpf_lsof_init(struct prof_dev *dev)
{
    struct bpfiter_ctx *ctx = zalloc(sizeof(*ctx));
    if (!ctx)
        return -1;
    dev->private = ctx;
    ctx->print_header = true; 
    ctx->skel = bpf_lsof_bpf__open();
    if (!ctx->skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        goto err;
    }
    ctx->skel->rodata->target_pid = dev->env->pidof;
    ctx->skel->rodata->target_port = dev->env->port;
    if (bpf_lsof_bpf__load(ctx->skel)) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto err;
    }
    return 0;
err:
    cleanup_ctx(ctx); 
    dev->private = NULL; 
    return -1;
}



/* iter */
static void *run_iterator(void *arg)
{
    struct bpfiter_ctx *ctx = arg;
    char buf[4096];
    bool iteration_completed = false;
    int iteration_count = 0;
    while (!ctx->stop && iteration_count < 1)
    {
        ssize_t len = read(ctx->iter_fd, buf, sizeof(buf));
        if (len < 0)
        {
            perror("read iter_fd");
            break;
        }
        else if (len == 0)
        {
            iteration_completed = true;
        }

        perf_buffer__poll(ctx->pb, 100);

        if (iteration_completed)
        {
            iteration_count++;

            cleanup_ctx(ctx); // 主动清理资源
            exit(0);          // 退出线程
        }
    }
    return NULL;
}
static int bpf_lsof_filter(struct prof_dev *dev)
{
    struct bpfiter_ctx *ctx = dev->private;
    struct env *env = dev->env;
    int map_fd;

    ctx->env = env;

    ctx->link = bpf_program__attach_iter(ctx->skel->progs.dump_task_file, NULL);

    if (libbpf_get_error(ctx->link))
    {
        fprintf(stderr, "Failed to attach iterator\n");
        goto error;
    }

    /* 创建迭代器FD */
    ctx->iter_fd = bpf_iter_create(bpf_link__fd(ctx->link));
    if (ctx->iter_fd < 0)
    {
        fprintf(stderr, "Failed to create iterator\n");
        goto error;
    }

    map_fd = bpf_map__fd(ctx->skel->maps.events);

    ctx->pb = perf_buffer__new(map_fd, 256, handle_events, NULL, ctx, NULL);

    if (libbpf_get_error(ctx->pb))
    {
        fprintf(stderr, "Failed to create perf buffer\n");
        goto error;
    }

    if (dev->env->output2)
    {
        ctx->output = fopen(dev->env->output2, "w");
        if (!ctx->output)
        {
            fprintf(stderr, "Failed to open output file %s\n", dev->env->output2);
            goto error;
        }
    }

    ctx->stop = false;
    if (pthread_create(&ctx->iter_thread, NULL, run_iterator, ctx))
    {
        fprintf(stderr, "Failed to create iterator thread\n");
        goto error;
    }

    return 0;

error:
    cleanup_ctx(ctx);
    return -1;
}

static void bpf_lsof_interval(struct prof_dev *dev)
{
    struct bpfiter_ctx *ctx = dev->private;
    FILE *out = ctx->output ? ctx->output : stdout;
    if (ctx->iter_fd >= 0)
    {
        char buf[4096];
        ssize_t len;
        lseek(ctx->iter_fd, 0, SEEK_SET);
        while ((len = read(ctx->iter_fd, buf, sizeof(buf))))
        {
            if (len < 0)
            {
                if (errno == EAGAIN || errno == EINTR)
                    continue;
                perror("read iter_fd");
                break;
            }

            perf_buffer__poll(ctx->pb, 10);
        }
    }

    fflush(out);
}

static void bpf_lsof_deinit(struct prof_dev *dev)
{
    struct bpfiter_ctx *ctx = dev->private;
    if (!ctx)
        return;

    ctx->stop = true;
    pthread_join(ctx->iter_thread, NULL);
    cleanup_ctx(ctx);
    dev->private = NULL;
}

static const char *bpf_lsof_desc[] = PROFILER_DESC("bpf:bpf_lsof",
                                                   "[OPTION...] [--comm] [--unix_file] [--tcp_listen][--port] [--grep] [--pidof] ",
                                                   "Monitor file operations using BPF perf events.", "",
                                                   "BPF-EVENT",
                                                   "    pid        Process ID",
                                                   "    path       Process command name", "",
                                                   "EXAMPLES",
                                                   "    " PROGRAME " bpf:bpf_lsof --port port_number",
                                                   "    " PROGRAME " bpf:bpf_lsof --grep filename",
                                                   "    " PROGRAME " bpf:bpf_lsof --path pathname",
                                                   "    " PROGRAME " bpf:bpf_lsof --tcp_listen --pidof target_pid",
                                                   "    " PROGRAME " bpf:bpf_lsof --unix_file --pidof target_pid");
static const char *bpf_lsof_args[] = PROFILER_ARGV("bpf:bpf_lsof",
                                                   PROFILER_ARGV_OPTION,
                                                   PROFILER_ARGV_PROFILER, "path", "unix_file", "tcp_listen", "port", "grep", "pidof", "output2");
struct monitor bpf_lsof = {
    .name = "bpf:bpf_lsof",
    .desc = bpf_lsof_desc,
    .argv = bpf_lsof_args,
    .pages = 4,
    .init = bpf_lsof_init,
    .filter = bpf_lsof_filter,
    .deinit = bpf_lsof_deinit,
    .interval = bpf_lsof_interval,
};
MONITOR_REGISTER(bpf_lsof)