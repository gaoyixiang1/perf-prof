#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_stack_iter.h"

char _license[] SEC("license") = "GPL";

SEC("iter/task")
int dump_task_stack(struct bpf_iter__task *ctx)
{
    struct task_struct *task = ctx->task;
    struct task_info info = {};

    if (!task)
        return 0;

    // 调试输出
    bpf_printk("Processing task: pid=%d", task->pid);
    
    info.pid = task->pid;
    bpf_probe_read_kernel_str(&info.comm, sizeof(info.comm), task->comm);
    
    // 内核兼容处理
    if (bpf_core_field_exists(task->__state)) {
        bpf_probe_read_kernel(&info.state, sizeof(info.state), &task->__state);
    } 

    // 直接输出到迭代器
    bpf_seq_write(ctx->meta->seq, &info, sizeof(info));
    
    return 0;
}