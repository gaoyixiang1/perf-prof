#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include "monitor.h"
#include <bpf-skel/bpf_stack_iter.h>
#include <bpf-skel/bpf_stack_iter.skel.h>

struct stack_iter_ctx {
    struct bpf_stack_iter_bpf *skel;
    struct bpf_link *link;
    int iter_fd;
    int perf_fd;
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

static void process_task_info(struct stack_iter_ctx *ctx, struct task_info *info)
{
    const char *state_str = state_to_str(info->state);

    if (ctx->print_header) {
        ctx->print_header = false;
        fprintf(ctx->output, "===== Task Info =====\n");
        fprintf(ctx->output, "%-8s %-16s %-12s\n", "PID", "COMM", "STATE");
    }
    fprintf(ctx->output, "%-8u %-16s %-12s\n", info->pid, info->comm, state_str);
}

// perf_event_open helper
static int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static int bpf_stack_iter_init(struct prof_dev *dev)
{
    struct stack_iter_ctx *ctx;
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    struct perf_event_attr attr = {
        .type = PERF_TYPE_SOFTWARE,
        .config = PERF_COUNT_SW_BPF_OUTPUT,
        .sample_type = PERF_SAMPLE_RAW,
        .wakeup_events = 1,
    };
    int perf_fd = -1;
    int map_fd=-1;
    int key;

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return -1;
    dev->private = ctx;

    setrlimit(RLIMIT_MEMLOCK, &rlim);

    ctx->skel = bpf_stack_iter_bpf__open();
    if (!ctx->skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        goto free_ctx;
    }
    if (bpf_stack_iter_bpf__load(ctx->skel)) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto destroy_skel;
    }

    ctx->link = bpf_program__attach_iter(ctx->skel->progs.dump_task_stack, NULL);
    if (!ctx->link) {
        fprintf(stderr, "Failed to attach iterator program\n");
        goto destroy_skel;
    }

    ctx->iter_fd = bpf_iter_create(bpf_link__fd(ctx->link));
    if (ctx->iter_fd < 0) {
        fprintf(stderr, "Failed to create iterator FD: %d\n", ctx->iter_fd);
        goto detach_link;
    }

    // 打开 perf event
    perf_fd = perf_event_open(&attr, -1, 0, -1, 0);
    if (perf_fd < 0) {
        fprintf(stderr, "perf_event_open failed: %s\n", strerror(errno));
        goto close_iter;
    }
    ctx->perf_fd = perf_fd;

    // 将 perf event fd 填到 BPF map
    
    map_fd = bpf_map__fd(ctx->skel->maps.stack_events);
    key = 0;
    if (bpf_map_update_elem(map_fd, &key, &perf_fd, BPF_ANY) < 0) {
        fprintf(stderr, "bpf_map_update_elem failed: %s\n", strerror(errno));
        goto close_perf;
    }

    ctx->output = stdout;
    ctx->print_header = true;
    return 0;

close_perf:
    close(perf_fd);
close_iter:
    close(ctx->iter_fd);
detach_link:
    bpf_link__destroy(ctx->link);
destroy_skel:
    bpf_stack_iter_bpf__destroy(ctx->skel);
free_ctx:
    free(ctx);
    return -1;
}

static void bpf_stack_iter_deinit(struct prof_dev *dev)
{
    struct stack_iter_ctx *ctx = dev->private;
    if (!ctx) return;
    if (ctx->perf_fd >= 0) close(ctx->perf_fd);
    if (ctx->iter_fd >= 0) close(ctx->iter_fd);
    if (ctx->link) bpf_link__destroy(ctx->link);
    if (ctx->skel) bpf_stack_iter_bpf__destroy(ctx->skel);
    free(ctx);
}

static void bpf_stack_iter_interval(struct prof_dev *dev)
{
    struct stack_iter_ctx *ctx = dev->private;
    char buf[1];

    // 触发迭代器执行
    if (ctx->iter_fd >= 0) {
        lseek(ctx->iter_fd, 0, SEEK_SET);
        if (read(ctx->iter_fd, buf, sizeof(buf)) < 0 && errno != EAGAIN) {
            perror("read iter_fd");
        }
    }

    // 轮询 perf event
    if (ctx->perf_fd >= 0) {
        while (1) {
            struct {
                struct perf_event_header header;
                char data[sizeof(struct task_info)];
            } event;
            ssize_t ret = read(ctx->perf_fd, &event, sizeof(event));
            if (ret < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    break;
                perror("read perf_fd");
                break;
            }
            if (ret < (ssize_t)sizeof(event.header))
                break;
            if (event.header.type == PERF_RECORD_SAMPLE) {
                struct task_info *info = (struct task_info *)event.data;
                process_task_info(ctx, info);
            }
        }
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