// #include "vmlinux.h"
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_core_read.h>
// #include <bpf/bpf_tracing.h>

// char _license[] SEC("license") = "GPL";

// SEC("iter/task")
// int dump_task_info(struct bpf_iter__task *ctx)
// {
//     bpf_printk("Debug: Entering BPF program");
//     struct seq_file *seq = ctx->meta->seq;
//     struct task_struct *task = ctx->task;

//     if (!task)
//         return 0;

//     // Print header on first iteration
//     if (ctx->meta->seq_num == 0) {
//         BPF_SEQ_PRINTF(seq, "%-8s %-16s\n", "PID", "COMM");
//     }
//     bpf_printk("Debug: PID=%d, COMM=%s", task->pid, task->comm);

//     BPF_SEQ_PRINTF(seq, "%-8d %-16s\n", task->pid, task->comm);
//     return 0;
// }


#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("iter/task")
int dump_task_info(struct bpf_iter__task *ctx)
{
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *task = ctx->task;

    bpf_printk("Debug: Entering BPF iter/task, seq_num=%llu", ctx->meta->seq_num);

    if (!task) {
        bpf_printk("Debug: Task is NULL");
        return 0;
    }

    // Print header on first iteration
    if (ctx->meta->seq_num == 0) {
        bpf_printk("Debug: Printing header");
        BPF_SEQ_PRINTF(seq, "%-8s %-16s\n", "PID", "COMM");
    }

    bpf_printk("Debug: PID=%d, COMM=%s", task->pid, task->comm);
    BPF_SEQ_PRINTF(seq, "%-8d %-16s\n", task->pid, task->comm);

    return 0;
}