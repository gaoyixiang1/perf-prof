#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "bpf_stack_iter.h"

char _license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} stack_events SEC(".maps");

SEC("iter/task")
int dump_task_stack(struct bpf_iter__task *ctx)
{
    struct task_struct *task = ctx->task;
    struct task_info info = {};

    if (!task)
        return 0;
    bpf_printk("1111");
    info.pid = task->pid;
    bpf_core_read_str(&info.comm, sizeof(info.comm), task->comm);
    bpf_core_read(&info.state, sizeof(info.state), &task->__state);

    bpf_perf_event_output(ctx, &stack_events, BPF_F_CURRENT_CPU, &info, sizeof(info));
    return 0;
}