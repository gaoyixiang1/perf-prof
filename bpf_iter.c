// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <unistd.h>
// #include <sys/types.h>
// #include <bpf/bpf.h>
// #include <bpf/libbpf.h>
// #include <monitor.h>
// #include <bpf-skel/"

// struct bpfiter_ctx {
//     struct bpf_iter_bpf *skel;  // BPF 骨架
//     struct bpf_link *link;      // 迭代器链接
//     int iter_fd;                // 迭代器文件描述符
//     FILE *output2;              // 输出文件（支持 --output2 参数）
//     bool print_header;          // 是否打印表头
//     int nr_ins;                 // 实例数（支持 --perins）
// };

// // 错误处理宏，参考 kvm-exit.c
// #define ERR(fmt, ...) fprintf(stderr, "[ERROR] " fmt ": %s\n", ##__VA_ARGS__, strerror(errno))

// // 初始化上下文，加载并挂载 BPF 迭代器
// static int bpf_iter_init(struct prof_dev *dev)
// {
//     struct bpfiter_ctx *ctx = zalloc(sizeof(*ctx));
//     if (!ctx) {
//         ERR("Failed to allocate context");
//         return -1;
//     }
//     dev->private = ctx;

//     // 加载 BPF 骨架
//     ctx->skel = bpf_iter_bpf__open_and_load();
//     if (!ctx->skel) {
//         ERR("Failed to open and load BPF skeleton");
//         goto failed;
//     }

//     // 挂载迭代器
//     ctx->link = bpf_program__attach_iter(ctx->skel->progs.dump_task_info, NULL);
//     if (libbpf_get_error(ctx->link)) {
//         ERR("Failed to attach iterator");
//         goto failed;
//     }

//     // 创建迭代器文件描述符
//     ctx->iter_fd = bpf_iter_create(bpf_link__fd(ctx->link));
//     if (ctx->iter_fd < 0) {
//         ERR("Failed to create iterator");
//         goto failed;
//     }

//     ctx->nr_ins = prof_dev_nr_ins(dev);
//     ctx->print_header = true;

//     // 支持 --output2 参数
//     if (dev->env->output2) {
//         ctx->output2 = fopen(dev->env->output2, "w");
//         if (!ctx->output2) {
//             ERR("Failed to open output file %s", dev->env->output2);
//             goto failed;
//         }
//     }

//     return 0;

// failed:
//     if (ctx->iter_fd >= 0) close(ctx->iter_fd);
//     if (ctx->link) bpf_link__destroy(ctx->link);
//     if (ctx->skel) bpf_iter_bpf__destroy(ctx->skel);
//     free(ctx);
//     dev->private = NULL;
//     return -1;
// }

// // 清理上下文
// static void bpf_iter_deinit(struct prof_dev *dev)
// {
//     struct bpfiter_ctx *ctx = dev->private;
//     if (!ctx) return;

//     if (ctx->output2) fclose(ctx->output2);
//     if (ctx->iter_fd >= 0) close(ctx->iter_fd);
//     if (ctx->link) bpf_link__destroy(ctx->link);
//     if (ctx->skel) bpf_iter_bpf__destroy(ctx->skel);
//     free(ctx);
//     dev->private = NULL;
// }

// // 处理迭代器输出
// static void bpf_iter_sample(struct prof_dev *dev, union perf_event *event, int instance)
// {
//     struct bpfiter_ctx *ctx = dev->private;
//     char buf[4096];
//     ssize_t len;

//     // 读取迭代器输出
//     while ((len = read(ctx->iter_fd, buf, sizeof(buf) - 1)) > 0) {
//         buf[len] = '\0';
//         // 输出到 stdout 或 output2 文件
//         if (ctx->output2) {
//             fprintf(ctx->output2, "%s", buf);
//             fflush(ctx->output2);
//         } else {
//             printf("%s", buf);
//             fflush(stdout);
//         }
//     }

//     if (len < 0 && errno != EINTR) {
//         ERR("Failed to read iterator");
//     }
// }

// // 格式化输出，参考 kvm-exit.c 的 interval 函数
// static void bpf_iter_interval(struct prof_dev *dev)
// {
//     struct bpfiter_ctx *ctx = dev->private;

//     // 打印表头，参考 kvm-exit.c 的 print_latency_node
//     if (ctx->print_header) {
//         ctx->print_header = false;
//         print_time(stdout);
//         printf("BPF Iterator: Task Information\n");
//         printf("%-8s %-16s\n", "PID", "COMM");
//         printf("-------- ----------------\n");
//     }

//     // 触发 sample 处理（实际输出在 sample 中完成）
//     // 这里仅重置 print_header 以支持下一次 interval
//     ctx->print_header = true;
// }

// // 描述和参数，参考 kvm-exit.c
// static const char *bpf_iter_desc[] = PROFILER_DESC("bpf:bpf_iter",
//     "[OPTION...] [--perins] [--than ns] [--output2 file]",
//     "Dump task information using BPF iterator.", "",
//     "BPF-EVENT",
//     "    pid        Process ID",
//     "    comm       Process command name", "",
//     "EXAMPLES",
//     "    "PROGRAME" bpf:bpf_iter -p 2347 -i 1000",
//     "    "PROGRAME" bpf:bpf_iter -C 1-4 -i 1000 --perins --output2 tasks.txt");
// static const char *bpf_iter_argv[] = PROFILER_ARGV("bpf:bpf_iter",
//     PROFILER_ARGV_OPTION,
//     PROFILER_ARGV_PROFILER, "perins", "than", "output2");
// struct monitor bpf_iter = {
//     .name = "bpf:bpf_iter",
//     .desc = bpf_iter_desc,
//     .argv = bpf_iter_argv,
//     .pages = 4,
//     .init = bpf_iter_init,
//     .deinit = bpf_iter_deinit,
//     .sample = bpf_iter_sample,
//     .interval = bpf_iter_interval,
// };
// MONITOR_REGISTER(bpf_iter)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <monitor.h>
#include <bpf-skel/bpf_iter.skel.h>

// 调试日志函数
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

struct bpfiter_ctx {
    struct bpf_iter_bpf *skel;  // BPF 骨架
    struct bpf_link *link;      // 迭代器链接
    int iter_fd;                // 迭代器文件描述符
    FILE *output2;              // 输出文件
    bool print_header;          // 是否打印表头
    pthread_t read_thread;      // 读取线程
    volatile bool stop;         // 停止标志
};

// 错误处理宏
#define ERR(fmt, ...) fprintf(stderr, "[ERROR] " fmt ": %s\n", ##__VA_ARGS__, strerror(errno))

// 读取线程函数
static void *read_iter_thread(void *arg)
{
    struct bpfiter_ctx *ctx = arg;
    char buf[4096];
    ssize_t len;
    FILE *out = ctx->output2 ? ctx->output2 : stdout;

    fprintf(stderr, "[DEBUG] Starting read thread\n");
    while (!ctx->stop) {
        len = read(ctx->iter_fd, buf, sizeof(buf) - 1);
        if (len > 0) {
            buf[len] = '\0';
            fprintf(out, "%s", buf);
            fflush(out);
            fprintf(stderr, "[DEBUG] Read %zd bytes: %s\n", len, buf);
        } else if (len < 0 && errno != EINTR) {
            ERR("Failed to read iterator");
            break;
        } else if (len == 0) {
            fprintf(stderr, "[DEBUG] Iterator read complete, re-attaching\n");
            // 重新创建迭代器
            close(ctx->iter_fd);
            ctx->iter_fd = bpf_iter_create(bpf_link__fd(ctx->link));
            if (ctx->iter_fd < 0) {
                ERR("Failed to re-create iterator");
                break;
            }
        }
        usleep(100000); // 避免 CPU 过载
    }
    return NULL;
}

// 初始化上下文并启动读取线程
static int bpf_iter_init(struct prof_dev *dev)
{
    struct bpfiter_ctx *ctx = zalloc(sizeof(*ctx));
    if (!ctx) {
        ERR("Failed to allocate context");
        return -1;
    }
    dev->private = ctx;

    // 启用 libbpf 调试日志
    libbpf_set_print(libbpf_print_fn);
    fprintf(stderr, "[DEBUG] Initializing BPF iterator\n");

    // 加载 BPF 骨架
    ctx->skel = bpf_iter_bpf__open_and_load();
    if (!ctx->skel) {
        ERR("Failed to open and load BPF skeleton");
        goto failed;
    }
    fprintf(stderr, "[DEBUG] BPF skeleton loaded\n");

    // 挂载迭代器
    ctx->link = bpf_program__attach_iter(ctx->skel->progs.dump_task_info, NULL);
    if (libbpf_get_error(ctx->link)) {
        ERR("Failed to attach iterator");
        goto failed;
    }
    fprintf(stderr, "[DEBUG] Iterator attached\n");

    // 创建迭代器文件描述符
    ctx->iter_fd = bpf_iter_create(bpf_link__fd(ctx->link));
    if (ctx->iter_fd < 0) {
        ERR("Failed to create iterator");
        goto failed;
    }
    fprintf(stderr, "[DEBUG] Iterator FD created\n");

    // 支持 --output2 参数
    if (dev->env->output2) {
        ctx->output2 = fopen(dev->env->output2, "w");
        if (!ctx->output2) {
            ERR("Failed to open output file %s", dev->env->output2);
            goto failed;
        }
    }

    ctx->print_header = true;
    ctx->stop = false;

    // 启动读取线程
    if (pthread_create(&ctx->read_thread, NULL, read_iter_thread, ctx)) {
        ERR("Failed to create read thread");
        goto failed;
    }
    fprintf(stderr, "[DEBUG] Read thread started\n");

    return 0;

failed:
    if (ctx->output2) fclose(ctx->output2);
    if (ctx->iter_fd >= 0) close(ctx->iter_fd);
    if (ctx->link) bpf_link__destroy(ctx->link);
    if (ctx->skel) bpf_iter_bpf__destroy(ctx->skel);
    free(ctx);
    dev->private = NULL;
    return -1;
}

// 清理上下文
static void bpf_iter_deinit(struct prof_dev *dev)
{
    struct bpfiter_ctx *ctx = dev->private;
    if (!ctx) return;

    fprintf(stderr, "[DEBUG] Deinitializing BPF iterator\n");
    ctx->stop = true;
    if (ctx->read_thread) {
        pthread_join(ctx->read_thread, NULL);
    }
    if (ctx->output2) fclose(ctx->output2);
    if (ctx->iter_fd >= 0) close(ctx->iter_fd);
    if (ctx->link) bpf_link__destroy(ctx->link);
    if (ctx->skel) bpf_iter_bpf__destroy(ctx->skel);
    free(ctx);
    dev->private = NULL;
}

// 格式化输出表头
static void bpf_iter_interval(struct prof_dev *dev)
{
    struct bpfiter_ctx *ctx = dev->private;

    if (ctx->print_header) {
        ctx->print_header = false;
        print_time(stdout);
        printf("BPF Iterator: Task Information\n");
        printf("%-8s %-16s\n", "PID", "COMM");
        printf("-------- ----------------\n");
    }
}

// 描述和参数
static const char *bpf_iter_desc[] = PROFILER_DESC("bpf:bpf_iter",
    "[OPTION...] [--perins] [--than ms] [--output2 file]",
    "Dump task information using BPF iterator.", "",
    "BPF-EVENT",
    "    pid        Process ID",
    "    comm       Process command name", "",
    "EXAMPLES",
    "    "PROGRAME" bpf:bpf_iter -p 2347 -i 10",
    "    "PROGRAME" bpf:bpf_iter -C 1-4 -i 10 --output2 tasks.txt");
static const char *bpf_iter_args[] = PROFILER_ARGV("bpf:bpf_iter",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_PROFILER, "perins", "than", "output2");
struct monitor bpf_iter = {
    .name = "bpf:bpf_iter",
    .desc = bpf_iter_desc,
    .argv = bpf_iter_args,
    .pages = 4,
    .init = bpf_iter_init,
    .deinit = bpf_iter_deinit,
    .interval = bpf_iter_interval,
};
MONITOR_REGISTER(bpf_iter)

