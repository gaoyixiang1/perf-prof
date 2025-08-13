#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_ps.h"

const volatile struct field_collection_config field_config = {};

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct task_info);
} task_info_storage SEC(".maps");

SEC("iter/task")
int dump_task_info(struct bpf_iter__task *ctx)
{
    struct task_struct *task = ctx->task;
    __u32 zero = 0, id;
    u64 sum_exec_runtime = 0;
    __u32 tgid, num_threads, pid;
    struct task_info *info;
    char raw_comm[TASK_COMM_LEN] = {};
    const char *default_tty = "?";
    struct percpu_counter *rss;
    struct pid *pgrp_pid = NULL;

    if (task == NULL)
        return 0;

    // grep模式
    if (field_config.grep_mode)
    {
        if(task->pid != task->tgid) 
            return 0;
        struct task_info info = {};
        info.pid = task->pid;
        bpf_probe_read_kernel_str(info.comm, sizeof(info.comm), task->comm);
        bpf_seq_write(ctx->meta->seq, &info, sizeof(info));
        return 0;
    }

    // child_pid模式
    if (field_config.child_pid_mode)
    {
        struct task_info info = {};
        info.pid = task->pid;
        info.ppid = BPF_CORE_READ(task, real_parent, pid);
        bpf_seq_write(ctx->meta->seq, &info, sizeof(info));
        return 0;
    }
    
    // pkill 模式
    if (field_config.pkill_mode)
    {
        struct task_info info = {};
        info.pid = task->pid;
        info.ppid = BPF_CORE_READ(task, real_parent, pid);
        bpf_probe_read_kernel_str(info.comm, sizeof(info.comm),task->comm);
        
        bpf_seq_write(ctx->meta->seq, &info, sizeof(info));
        return 0;
    }
    // //--pid
    // if (field_config.pid > 0 && task->pid != field_config.pid)
    // {
    //     return 0;
    // }

    // if (field_config.only_process && task->pid != task->tgid)
    //     return 0;

    info = bpf_map_lookup_elem(&task_info_storage, &zero);
    if (!info)
        return 0;


    // 基础字段总是采集
    if (field_config.collect_basic)
    {
        info->pid = task->pid;
        info->ppid = BPF_CORE_READ(task, real_parent, pid);

        // comm
        bpf_probe_read_kernel_str(raw_comm, sizeof(raw_comm), task->comm);
        if (task->flags & PF_KTHREAD)
        {
            info->comm[0] = '[';
            __builtin_memcpy(&info->comm[1], raw_comm, sizeof(raw_comm));
            int len = 0;
            for (; len < sizeof(raw_comm) && raw_comm[len] != '\0'; len++)
                ;
            info->comm[len + 1] = ']';
            info->comm[len + 2] = '\0';
        }
        else
        {
            bpf_probe_read_kernel_str(info->comm, sizeof(info->comm), raw_comm);
        }
    }

    // 线程相关字段
    if (field_config.collect_thread)
    {
        tgid = BPF_CORE_READ(task, tgid);
        num_threads = BPF_CORE_READ(task, signal, nr_threads);
        pid = (num_threads > 1) ? tgid : task->pid;
        info->tgid = tgid;
        info->num_threads = num_threads;
        if (!field_config.collect_basic)
        {
            info->pid = pid;
        }
    }

    // 用户相关字段
    if (field_config.collect_user)
    {
        info->uid = BPF_CORE_READ(task, cred, uid.val);
        info->ruid = BPF_CORE_READ(task, real_cred, uid.val);
        info->rgid = BPF_CORE_READ(task, real_cred, gid.val);
    }

    // CPU相关字段
    if (field_config.collect_cpu)
    {
        info->cpu = BPF_CORE_READ(task, wake_cpu);
        info->policy = BPF_CORE_READ(task, policy);
        info->rt_priority = BPF_CORE_READ(task, rt_priority);
    }

    // 状态相关字段
    if (field_config.collect_state)
    {
        info->state = BPF_CORE_READ(task, __state);
        info->exit_state = BPF_CORE_READ(task, exit_state);
        info->flags = BPF_CORE_READ(task, flags);
    }

    // 扩展字段
    if (field_config.collect_extended)
    {
        info->vm_locked = BPF_CORE_READ(task, mm, locked_vm) > 0 ? true : false;
    }

    // 时间相关字段
    if (field_config.collect_time)
    {
        sum_exec_runtime = BPF_CORE_READ(task, se.sum_exec_runtime);
        u64 total_jiffies = sum_exec_runtime / NSEC_PER_TICK;
        info->sum_time = total_jiffies;
        info->start_boottime = BPF_CORE_READ(task, start_boottime);
    }

    // TTY相关字段
    if (field_config.collect_tty)
    {
        bpf_probe_read_kernel_str(info->tty, sizeof(info->tty), default_tty);
    }

    struct signal_struct *signal = task->signal;

    if (signal)
    {
        // TTY相关字段
        if (field_config.collect_tty)
        {
            info->tty_pgrp = BPF_CORE_READ(signal, pids[2], numbers[0].nr);

            // tty 名称
            struct tty_struct *tty =signal->tty;
            if (tty)
            {
                const char *name_ptr = BPF_CORE_READ(tty, name);
                if (name_ptr)
                {
                    bpf_probe_read_kernel_str(info->tty, sizeof(info->tty), name_ptr);
                }
            }
        }

    info->sid = BPF_CORE_READ(signal, pids[3], numbers[0].nr)==info->tgid;
        

        // 线程相关字段
        if (field_config.collect_thread)
        {
            // 获取当前命名空间
            struct pid_namespace *ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children);
            int level = BPF_CORE_READ(ns, level);
            // tid/lwp
            struct pid *pid_struct = BPF_CORE_READ(task, thread_pid);
            info->lwp = -1;
            if (pid_struct && level >= 0 && level < 32)
            {
                struct upid upid = BPF_CORE_READ(pid_struct, numbers[level]);
                info->lwp = upid.nr;
            }

            struct pid *pgrp_pid = BPF_CORE_READ(signal, pids[PIDTYPE_PGID]);
            info->tpgid = -1;
            if (pgrp_pid && level >= 0 && level < 32)
            {
                struct upid upid = BPF_CORE_READ(pgrp_pid, numbers[level]);
                info->tpgid = upid.nr;
            }
        }

       
    }

    // 时间相关字段
    if (field_config.collect_time)
    {
        s64 boottime_ns = 0;
        struct nsproxy *nsproxy =task->nsproxy;
        if (nsproxy)
        {
            struct time_namespace *time_ns = nsproxy->time_ns;
            if (time_ns)
            {
                struct timens_offsets offsets = BPF_CORE_READ(time_ns, offsets);
                struct timespec64 boottime = offsets.boottime;
                boottime_ns = (s64)boottime.tv_sec * 1000000000LL + boottime.tv_nsec;
            }
        }

        u64 real_start_boottime = info->start_boottime + boottime_ns;
        info->start_time = real_start_boottime / (1000000000ULL / HZ);
    }

    // CPU相关字段
    if (field_config.collect_cpu)
    {
        info->pri = BPF_CORE_READ(task, prio) - MAX_RT_PRIO;
        int static_prio = BPF_CORE_READ(task, static_prio);
        info->ni = PRIO_TO_NICE(static_prio);
    }

    // 内存相关字段
    if (field_config.collect_memory)
    {
        info->rss = BPF_CORE_READ(task, mm, rss_stat[0].count) + BPF_CORE_READ(task, mm, rss_stat[1].count) + BPF_CORE_READ(task, mm, rss_stat[3].count);
        info->total_vm = BPF_CORE_READ(task, mm, total_vm);
    }

    bpf_seq_write(ctx->meta->seq, info, sizeof(*info));
    return 0;
}
char _license[] SEC("license") = "GPL";