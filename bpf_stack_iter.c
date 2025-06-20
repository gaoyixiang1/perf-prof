#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include "monitor.h"
#include <bpf-skel/bpf_stack_iter.h>
#include <bpf-skel/bpf_stack_iter.skel.h>

struct stack_iter_ctx {
    struct bpf_stack_iter_bpf *skel;
    struct bpf_link *link;
    int iter_fd;
    FILE *output;
    bool print_header;
};

static const char *state_to_str(long state)
{
    switch (state) {
        case 0: return "RUNNING";
        case 1: return "INTERRUPTIBLE";
        case 2: return "UNINTERRUPTIBLE";
        case 4: return "STOPPED";
        case 8: return "TRACED";
        case 16: return "DEAD";
        case 32: return "ZOMBIE";
        default: return "UNKNOWN";
    }
}

static void process_task_info(struct stack_iter_ctx *ctx, const struct task_info *info)
{
    const char *state_str = state_to_str(info->state);

    if (ctx->print_header) {
        ctx->print_header = false;
        fprintf(ctx->output, "===== Task Info =====\n");
        fprintf(ctx->output, "%-8s %-16s %-12s\n", "PID", "COMM", "STATE");
    }
    fprintf(ctx->output, "%-8u %-16s %-12s\n", info->pid, info->comm, state_str);
}

static int read_iter_data(struct stack_iter_ctx *ctx)
{
    char buf[4096];
    ssize_t len;
    size_t pos = 0;
    int task_count = 0;

    // 重置迭代器位置
    if (lseek(ctx->iter_fd, 0, SEEK_SET) < 0) {
        perror("lseek iter_fd");
        return -1;
    }
    
    // 读取迭代器数据
    while ((len = read(ctx->iter_fd, buf, sizeof(buf)))) {
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            perror("read iter_fd");
            return -1;
        }
        
        if (len == 0) // 数据结束
            break;
        
        // 处理读取到的数据
        pos = 0;
        while (pos + sizeof(struct task_info) <= (size_t)len) {
            const struct task_info *info = (const struct task_info *)(buf + pos);
            process_task_info(ctx, info);
            pos += sizeof(struct task_info);
            task_count++;
        }
        
        // 处理不完整的数据块
        if (pos < (size_t)len) {
            fprintf(stderr, "Warning: Incomplete task info (%zu bytes remaining)\n", (size_t)len - pos);
        }
    }
    
    return task_count;
}

static int bpf_stack_iter_init(struct prof_dev *dev)
{
    LIBBPF_OPTS(bpf_iter_attach_opts, opts);
  int err;
       struct stack_iter_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return -1;
    dev->private = ctx;

    ctx->skel = bpf_stack_iter_bpf__open();
    if (!ctx->skel)
        goto free_ctx;
  
    err = bpf_stack_iter_bpf__load(ctx->skel);
    // if (bpf_stack_iter_bpf__load(ctx->skel))
    //     goto destroy_skel;
    if (err) {
    char buf[256];
    libbpf_strerror(err, buf, sizeof(buf));
    fprintf(stderr, "Failed to load BPF skeleton: %s\n", buf);
    goto destroy_skel;
}
    // 附加迭代器程序
    ctx->link = bpf_program__attach_iter(ctx->skel->progs.dump_task_stack, &opts);
    if (!ctx->link) {
        fprintf(stderr, "Failed to attach iterator program: %s\n", strerror(errno));
        goto destroy_skel;
    }

    // 创建迭代器文件描述符
    ctx->iter_fd = bpf_iter_create(bpf_link__fd(ctx->link));
    if (ctx->iter_fd < 0) {
        fprintf(stderr, "Failed to create iterator FD: %s\n", strerror(errno));
        goto detach_link;
    }

    fprintf(stderr, "BPF iterator initialized successfully! Iter FD: %d\n", ctx->iter_fd);
    
    ctx->output = stdout;
    ctx->print_header = true;
    return 0;

detach_link:
    if (ctx->link) bpf_link__destroy(ctx->link);
destroy_skel:
    if (ctx->skel) bpf_stack_iter_bpf__destroy(ctx->skel);
free_ctx:
    free(ctx);
    return -1;
}

static void bpf_stack_iter_deinit(struct prof_dev *dev)
{
    struct stack_iter_ctx *ctx = dev->private;
    if (!ctx) return;
    
    if (ctx->iter_fd >= 0) close(ctx->iter_fd);
    if (ctx->link) bpf_link__destroy(ctx->link);
    if (ctx->skel) bpf_stack_iter_bpf__destroy(ctx->skel);
    free(ctx);
}

static void bpf_stack_iter_interval(struct prof_dev *dev)
{
    struct stack_iter_ctx *ctx = dev->private;
    
    // 读取并处理迭代器数据
    int task_count = read_iter_data(ctx);
    if (task_count > 0) {
        fprintf(stderr, "Processed %d tasks\n", task_count);
    } else if (task_count < 0) {
        fprintf(stderr, "Error reading iterator data\n");
    }
    
    fflush(ctx->output);
    ctx->print_header = true;
}

static void bpf_stack_iter_sigusr(struct prof_dev *dev, int signum)
{
    return;
}

static const char *bpf_stack_iter_desc[] = PROFILER_DESC("bpf:stack_iter",
    "[OPTION...]",
    "Capture process PID information", "",
    "BPF-ITER",
    "    dump_task_stack: Collects task PID", "",
    "EXAMPLES",
    "    "PROGRAME" bpf:stack_iter -i 5000");

static const char *bpf_stack_iter_argv[] = PROFILER_ARGV("bpf:stack_iter",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_PROFILER, NULL);

struct monitor bpf_stack_iter = {
    .name = "bpf:stack_iter",
    .desc = bpf_stack_iter_desc,
    .argv = bpf_stack_iter_argv,
    .init = bpf_stack_iter_init,
    .deinit = bpf_stack_iter_deinit,
    .interval = bpf_stack_iter_interval,
    .sigusr = bpf_stack_iter_sigusr,
};
MONITOR_REGISTER(bpf_stack_iter)