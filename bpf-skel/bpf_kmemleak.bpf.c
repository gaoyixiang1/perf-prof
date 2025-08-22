    #include "vmlinux.h"
    #include <bpf/bpf_helpers.h>
    #include <bpf/bpf_tracing.h>
    #include <bpf/bpf_core_read.h>
    #include "bpf_kmemleak.h"

    #ifndef PERF_MAX_STACK_DEPTH
    #define PERF_MAX_STACK_DEPTH 127
    #endif

    struct trace_event_raw_kmem_alloc {
        unsigned long long unused;
        unsigned long ptr;
        size_t bytes_req;
        size_t bytes_alloc;
        gfp_t gfp_flags;
        int node;
    };

    struct trace_event_raw_kmem_free {
        unsigned long long unused;
        unsigned long ptr;
    };

    struct {
        __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
        __uint(key_size, sizeof(u32));
        __uint(value_size, sizeof(u32));
    } events SEC(".maps");

    struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1000000); 
        __type(key, unsigned long);
        __type(value, struct kmem_event);
    } allocations SEC(".maps");

    struct {
        __uint(type, BPF_MAP_TYPE_STACK_TRACE);
        __uint(key_size, sizeof(u32));
        __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
        __uint(max_entries, 10000);
    } stack_traces SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} timestamps SEC(".maps");


// 通用分配处理
static __always_inline void handle_alloc(unsigned long ptr, size_t size, void *ctx)
{
    struct kmem_event event = {};
    u32 stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
    u64 ts = bpf_ktime_get_ns(); 

    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.ptr = ptr;
    event.size = size;
    event.is_alloc = 1;
    event.stack_id = stack_id >= 0 ? stack_id : -1;
    event.time = ts; 
    u32 zero = 0;
    u64 *last_ts = bpf_map_lookup_elem(&timestamps, &zero);
    if (last_ts) {

        if (ts <= *last_ts) {
            ts = *last_ts + 1;
        }
        *last_ts = ts;
    } else {
        bpf_map_update_elem(&timestamps, &zero, &ts, BPF_ANY);
    }
    event.time = ts;

    int ret = bpf_map_update_elem(&allocations, &ptr, &event, BPF_ANY);
    if (ret < 0) {
        bpf_printk("Failed to update allocations map for ptr=0x%lx, ret=%d\n", ptr, ret);
    }

    ret = bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    if (ret < 0) {
        bpf_printk("Failed to output kmalloc event, ret=%d\n", ret);
    }
}

static __always_inline void handle_free(unsigned long ptr, void *ctx)
{
    struct kmem_event *alloc_event;
    struct kmem_event event = {};
    u64 ts = bpf_ktime_get_ns();  
    alloc_event = bpf_map_lookup_elem(&allocations, &ptr);
    event.ptr = ptr;
    event.is_alloc = 0;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    u32 zero = 0;
    u64 *last_ts = bpf_map_lookup_elem(&timestamps, &zero);
    if (last_ts) {
        if (ts <= *last_ts) {
            ts = *last_ts + 1;
        }
        *last_ts = ts;
    } else {
        bpf_map_update_elem(&timestamps, &zero, &ts, BPF_ANY);
    }
     event.time = ts;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    
    if (alloc_event) {
        event.size = alloc_event->size;
        event.stack_id = -1;
        int ret = bpf_map_delete_elem(&allocations, &ptr);
        if (ret < 0) {
            bpf_printk("Failed to delete allocation for ptr=0x%lx, ret=%d\n", ptr, ret);
        }
    } else {
        event.size = 0;
        event.stack_id = -1;
    }

    int ret = bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    if (ret < 0) {
        bpf_printk("Failed to output kfree event, ret=%d\n", ret);
    }
}


SEC("tracepoint/kmem/dummy_alloc")
int trace_kmalloc(struct trace_event_raw_kmem_alloc *ctx)
{
    handle_alloc((unsigned long)ctx->ptr, ctx->bytes_alloc, ctx);
    return 0;
}

SEC("tracepoint/kmem/dummy_free")
int trace_kfree(struct trace_event_raw_kmem_free *ctx)
{
    handle_free((unsigned long)ctx->ptr, ctx);
    return 0;
}


SEC("kprobe/dummy_kalloc")
int BPF_KPROBE(dummy_kalloc)
{
    unsigned long ptr = PT_REGS_RC(ctx);
    size_t size = PT_REGS_PARM1(ctx);
    handle_alloc(ptr, size, ctx);
    return 0;
}

SEC("kprobe/dummy_kfree")
int BPF_KPROBE(dummy_kfree)
{
    unsigned long ptr = PT_REGS_PARM1(ctx);
    handle_free(ptr, ctx);
    return 0;
}

char _license[] SEC("license") = "GPL";