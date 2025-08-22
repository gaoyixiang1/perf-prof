#ifndef __BPF_KMEMLEAK_H
#define __BPF_KMEMLEAK_H

#define TASK_COMM_LEN 16
#define MAX_STACK_DEPTH 127
#define MAX_LEAK_GROUPS 4096  
#define MAX_TRACE_FUNCS 8
#define CLOCK_REALTIME			0
#define CLOCK_MONOTONIC			1
#define HASH_TABLE_SIZE 8191  
struct leak_key {
    int depth;
    __u64 stack[MAX_STACK_DEPTH];
};
struct leak_hash_entry {
    struct leak_key key;
    unsigned long total_bytes;
    int count;
    struct leak_hash_entry *next;
};


struct leak_info {
    struct leak_key key;
    unsigned long total_bytes;
    int count;
};
struct kmem_event {
    unsigned long ptr;        
    size_t size;              
    int is_alloc;            
    pid_t pid;              
    char comm[TASK_COMM_LEN];
    int stack_id;             
    __u64 time;              
} __attribute__((packed));    

struct kmem_stats {
    __u64 alloc_count;
    __u64 free_count;
    __u64 total_alloc_size;
    __u64 total_free_size;
    __u64 leaked_count;
    __u64 leaked_size;
};

// 用于跟踪事件丢失的结构
struct kmemleak_lost {
    u64 start_time;
    u64 end_time;
    u64 lost_events;
    struct list_head lost_link;
};

struct trace_func {
    char class[64];
    char func[64];
};
struct trace_func_list {
    struct trace_func funcs[MAX_TRACE_FUNCS];
    int count;
};
#endif