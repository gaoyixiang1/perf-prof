#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <monitor.h>
#include <bpf-skel/bpf_kmemleak.skel.h>
#include <trace_helpers.h>
#include <linux/list.h>
#include <bpf-skel/bpf_kmemleak.h>

struct event_node {
    struct kmem_event event;
    struct list_head list;
};
struct bpf_ctx {
    struct env *env;
    struct bpf_kmemleak_bpf *skel;
    struct perf_buffer *pb;
    FILE *output;
    bool print_header;
    pthread_t poll_thread;
    char *flamegraph;
    volatile bool stop;
    bool leak_reported;
    struct kmem_stats stats;
    pthread_mutex_t stats_mutex;
    struct list_head lost_list; 
    pthread_t leak_scan_thread;
    struct ksyms *ksyms;
    __u64 last_event_ts;
     struct list_head event_queue;
    pthread_mutex_t event_queue_mutex;
    pthread_cond_t event_queue_cond;
    pthread_t order_thread;
    volatile bool order_thread_stop;
    __u64 start_mono_time;  
    time_t start_real_time;

};
static void *order_worker(void *arg);
static void process_event(struct bpf_ctx *ctx, struct kmem_event *event);
static int event_time_cmp(const void *a, const void *b);
static void process_event_queue(struct bpf_ctx *ctx);
static int stack_equal(const struct leak_key *a, const struct leak_key *b);
static void report_leaks(struct bpf_ctx *ctx);
static void print_stack_trace(struct bpf_ctx *ctx, int stack_id);
static void *leak_scan_worker(void *arg);
static void perf_event_callback(void *ctx, int cpu, void *data, __u32 size);

static void print_stats(struct bpf_ctx *ctx);
static void *poll_perf_buffer(void *arg);



static int parse_class_func(const char *str, struct trace_func *out)
{
    const char *sep = strchr(str, ':');
    size_t class_len, func_len;
    if (!sep) return -1;
    class_len = sep - str;
    func_len = strlen(sep + 1);
    if (class_len >= sizeof(out->class) || func_len >= sizeof(out->func))
        return -1;
    strncpy(out->class, str, class_len);
    out->class[class_len] = '\0';
    strncpy(out->func, sep + 1, func_len);
    out->func[func_len] = '\0';
    return 0;
}

static int parse_class_func_list(const char *str, struct trace_func_list *out)
{
    char *input = strdup(str);
    char *saveptr = NULL; 
    char *token;
    int idx = 0;
    if (!input) return -1;
    token = strtok_r(input, ",", &saveptr);
    while (token && idx < MAX_TRACE_FUNCS) {
        if (parse_class_func(token, &out->funcs[idx]) == 0) {
            idx++;
        } else {
            fprintf(stderr, "Invalid tracepoint format: %s\n", token);
            free(input);
            return -1;
        }
        token = strtok_r(NULL, ",", &saveptr);
    }
    out->count = idx;
    free(input);
    return 0;
}

static void export_flamegraph(struct bpf_ctx *ctx, struct leak_info *groups, int group_cnt, const char *filename)
{
    FILE *fp = NULL;
    int i, j;
    char buf[4096] = {0};
    char clean_name[256];
    const char *name;
    const struct ksym *ksym;
    char *p;
    int n;
    const char *s;
    char *d;
    
    fp = fopen(filename, "w");
    if (!fp) return;
    
    for (i = 0; i < group_cnt; i++) {
        p = buf;
        buf[0] = '\0';
        
        for (j = groups[i].key.depth - 1; j >= 0; j--) {
            __u64 addr = groups[i].key.stack[j];
            ksym = ksyms__map_addr(ctx->ksyms, addr);
            name = ksym ? ksym->name : "[unknown]";
            
            d = clean_name;
            for (s = name; *s && d < clean_name + sizeof(clean_name) - 1; s++) {
                *d++ = (*s == ';' || *s == ':' || *s == '(' || *s == ')') ? '_' : *s;
            }
            *d = '\0';
            
            n = snprintf(p, sizeof(buf) - (p-buf), "%s%s", 
                        (j == groups[i].key.depth-1) ? "" : ";", 
                        clean_name);
            if (n < 0 || n >= (int)(sizeof(buf) - (p-buf))) break;
            p += n;
        }
        fprintf(fp, "%s %lu\n", buf, groups[i].total_bytes);
    }
    fclose(fp);
    printf("Flamegraph data written to %s\n", filename);
}
static int stack_equal(const struct leak_key *a, const struct leak_key *b)
{
    if (a->depth != b->depth) return 0;
    
    if (a->depth > 0) {
        if (a->stack[0] != b->stack[0]) return 0;
        if (a->stack[a->depth-1] != b->stack[b->depth-1]) return 0;
    }
    
    return memcmp(a->stack, b->stack, a->depth * sizeof(__u64)) == 0;
}

static uint32_t stack_hash(const struct leak_key *key)
{
    uint32_t hash = 0;
    for (int i = 0; i < key->depth; i++) {
        hash = (hash << 5) - hash + (key->stack[i] & 0xFFFFFFFF);
        hash ^= (key->stack[i] >> 32);
    }
    return hash % HASH_TABLE_SIZE;
}

static void *leak_scan_worker(void *arg)
{
    struct bpf_ctx *ctx = arg;
    int map_fd;
    const __u64 LEAK_TIME_NS = 10ULL * 1000 * 1000 * 1000;
    const int BATCH_SIZE = 5000;
    unsigned long *keys = NULL;
    int key_count = 0;
    int max_keys = 0;
    struct timespec ts;
    __u64 now;
    unsigned long key = 0;
    unsigned long next_key;
    int processed;
    int batch_end;
    int i;
    struct kmem_event event;
    
    if (!ctx || !ctx->skel) return NULL;
    
    map_fd = bpf_map__fd(ctx->skel->maps.allocations);
    
    while (!ctx->stop) {
        clock_gettime(CLOCK_MONOTONIC, &ts);
        now = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
        key_count = 0;
        key = 0;
        
        while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
            unsigned long *new_keys;
            if (key_count >= max_keys) {
                max_keys = max_keys ? max_keys * 2 : 10240;
                new_keys = realloc(keys, max_keys * sizeof(unsigned long));
                if (!new_keys) break;
                keys = new_keys;
            }
            keys[key_count++] = next_key;
            key = next_key;
        }

        processed = 0;
        while (processed < key_count && !ctx->stop) {
            batch_end = processed + BATCH_SIZE;
            if (batch_end > key_count) {
                batch_end = key_count;
            }
            
            for (i = processed; i < batch_end; i++) {
                if (bpf_map_lookup_elem(map_fd, &keys[i], &event) == 0) {
                    if (event.is_alloc && now > event.time &&
                        now - event.time > LEAK_TIME_NS) {
                        printf("\n[LEAK DETECTED] ptr=0x%lx size=%lu pid=%d comm=%s\n",
                               event.ptr, event.size, event.pid, event.comm);
                        if (event.stack_id != -1) {
                            print_stack_trace(ctx, event.stack_id);
                        }
                    }
                }
            }
            
            processed = batch_end;
            
            if (processed < key_count) {
                usleep(500);
            }
        }

        for (i = 0; i < 50 && !ctx->stop; i++) {
            usleep(100000);
        }
    }

    free(keys);
    return NULL;
}
void report_leaks(struct bpf_ctx *ctx)
{
    int map_fd;
    struct leak_hash_entry **hash_table = NULL;
    struct leak_hash_entry *entry, *tmp;
    int group_cnt = 0;
    unsigned long key = 0, next_key;
    struct kmem_event event;
    __u64 stack[MAX_STACK_DEPTH];
    struct leak_key lkey;
    uint32_t idx;
    int found;
    struct leak_info *groups = NULL;
    int i, j;
    int group_idx = 0;
    const struct ksym *ksym;
    
    map_fd = bpf_map__fd(ctx->skel->maps.allocations);
    hash_table = calloc(HASH_TABLE_SIZE, sizeof(struct leak_hash_entry*));
    if (!hash_table) {
        fprintf(stderr, "Failed to allocate hash table\n");
        return;
    }

    key = 0;
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &event) == 0) {
            if (event.is_alloc && event.stack_id >= 0) {
                if (bpf_map_lookup_elem(bpf_map__fd(ctx->skel->maps.stack_traces),
                                      &event.stack_id, stack) != 0) {
                    key = next_key;
                    continue;
                }
                
                lkey.depth = 0;
                while (lkey.depth < MAX_STACK_DEPTH && stack[lkey.depth])
                    lkey.depth++;
                memcpy(lkey.stack, stack, lkey.depth * sizeof(__u64));
                
                idx = stack_hash(&lkey);
                found = 0;
                
                for (entry = hash_table[idx]; entry; entry = entry->next) {
                    if (stack_equal(&entry->key, &lkey)) {
                        entry->total_bytes += event.size;
                        entry->count++;
                        found = 1;
                        break;
                    }
                }
                
                if (!found) {
                    entry = malloc(sizeof(struct leak_hash_entry));
                    if (entry) {
                        entry->key = lkey;
                        entry->total_bytes = event.size;
                        entry->count = 1;
                        entry->next = hash_table[idx];
                        hash_table[idx] = entry;
                        group_cnt++;
                    }
                }
            }
        }
        key = next_key;
    }

    if (group_cnt > 0) {
        groups = calloc(group_cnt, sizeof(struct leak_info));
    }

    if (groups) {
        group_idx = 0;
        for (i = 0; i < HASH_TABLE_SIZE; i++) {
            for (entry = hash_table[i]; entry; entry = entry->next) {
                groups[group_idx].key = entry->key;
                groups[group_idx].total_bytes = entry->total_bytes;
                groups[group_idx].count = entry->count;
                group_idx++;
            }
        }
    }

    if (group_cnt == 0) {
        printf("No leaks detected.\n");
    } else {
        printf("\nLEAKED BYTES REPORT :\n");
        for (i = 0; i < group_cnt; i++) {
            printf("Leak of %lu bytes in %d objects allocated from:\n",
               groups[i].total_bytes, groups[i].count);
            for (j = 0; j < groups[i].key.depth; j++) {
                __u64 addr = groups[i].key.stack[j];
                ksym = ksyms__map_addr(ctx->ksyms, addr);
                printf("     %016llx %s+0x%llx ([kernel.kallsyms])\n",
                        addr, ksym ? ksym->name : "[unknown]",
                       ksym ? addr - ksym->addr : 0);
            }
        }
    }

    if (ctx->flamegraph && groups && group_cnt > 0) {
        export_flamegraph(ctx, groups, group_cnt, ctx->flamegraph);
    }

    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        entry = hash_table[i];
        while (entry) {
            tmp = entry->next;
            free(entry);
            entry = tmp;
        }
    }
    free(hash_table);
    free(groups);
}
static void perf_event_lost_cb(void *ctx, int cpu, __u64 lost_cnt)
{
    struct bpf_ctx *bpf_ctx = ctx;
    struct timespec ts;
    struct kmemleak_lost *lost ;
    __u64 lost_time;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    lost_time = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    lost = malloc(sizeof(*lost));
    if (!lost) return;
    lost->start_time = bpf_ctx->last_event_ts;
    lost->end_time = lost_time;
    lost->lost_events = lost_cnt;
    list_add_tail(&lost->lost_link, &bpf_ctx->lost_list);

}

static int event_time_cmp(const void *a, const void *b)
{
    const struct kmem_event *ea = (const struct kmem_event *)a;
    const struct kmem_event *eb = (const struct kmem_event *)b;
    
    if (ea->time < eb->time) return -1;
    if (ea->time > eb->time) return 1;
    return 0;
}
static void process_event(struct bpf_ctx *ctx, struct kmem_event *event)
{
    char time_str[32];
    struct tm *tm;
    time_t t;
    __u64 real_ns;
 
    ctx->last_event_ts = event->time;

    real_ns = ctx->start_real_time * 1000000000ULL + 
                   (event->time - ctx->start_mono_time);
    t = (time_t)(real_ns / 1000000000ULL);
    tm = localtime(&t);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm);

    pthread_mutex_lock(&ctx->stats_mutex);
    if (event->is_alloc) {
        ctx->stats.alloc_count++;
        ctx->stats.total_alloc_size += event->size;
    } else {
        ctx->stats.free_count++;
        ctx->stats.total_free_size += event->size;
    }
    pthread_mutex_unlock(&ctx->stats_mutex);
}

static void *order_worker(void *arg)
{
    struct bpf_ctx *ctx = arg;
    struct timespec ts;
    
    while (!ctx->order_thread_stop) {
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 1;  
        
        pthread_mutex_lock(&ctx->event_queue_mutex);
        pthread_cond_timedwait(&ctx->event_queue_cond, &ctx->event_queue_mutex, &ts);
        
        if (!list_empty(&ctx->event_queue)) {
            process_event_queue(ctx);
        }
        
        pthread_mutex_unlock(&ctx->event_queue_mutex);
    }
    
    pthread_mutex_lock(&ctx->event_queue_mutex);
    if (!list_empty(&ctx->event_queue)) {
        process_event_queue(ctx);
    }
    pthread_mutex_unlock(&ctx->event_queue_mutex);
    
    return NULL;
}


static void process_event_queue(struct bpf_ctx *ctx)
{
    struct event_node *node, *tmp;
    int count = 0, i = 0;
    struct kmem_event **events;
    struct list_head temp_list;
  
    list_for_each_entry(node, &ctx->event_queue, list) {
        count++;
    }
    
    if (count == 0) return;

    events = malloc(count * sizeof(*events));
    if (!events) return;

    INIT_LIST_HEAD(&temp_list);
    list_for_each_entry_safe(node, tmp, &ctx->event_queue, list) {
        list_move_tail(&node->list, &temp_list);
        events[i++] = &node->event;
    }
    
    qsort(events, count, sizeof(*events), event_time_cmp);
   
    for (i = 0; i < count; i++) {
        process_event(ctx, events[i]);
    }
    
    list_for_each_entry_safe(node, tmp, &temp_list, list) {
        list_del(&node->list);
        free(node);
    }
    
    free(events);
}

static void perf_event_callback(void *ctx, int cpu, void *data, __u32 size)
{
    
    struct bpf_ctx *bpf_ctx = ctx;
    struct kmem_event *event = data;
    ((struct bpf_ctx *)ctx)->last_event_ts = event->time;
    

    if (size != sizeof(struct kmem_event)) {
        for (__u32 i = 0; i < size && i < 64; i++) {
            fprintf(stderr, "%02x ", ((unsigned char *)data)[i]);
        }
        fprintf(stderr, "\n");
        return;
    }
    bpf_ctx->last_event_ts = event->time;
    if (bpf_ctx->env->time_order) {
        struct event_node *node = malloc(sizeof(*node));
        if (!node) return;
        
        memcpy(&node->event, event, sizeof(*event));
        INIT_LIST_HEAD(&node->list);
        
        pthread_mutex_lock(&bpf_ctx->event_queue_mutex);
        list_add_tail(&node->list, &bpf_ctx->event_queue);
        pthread_cond_signal(&bpf_ctx->event_queue_cond);
        pthread_mutex_unlock(&bpf_ctx->event_queue_mutex);
    } else{
    char time_str[32];
    time_t t;
    struct tm *tm;
    FILE *out = bpf_ctx->output ? bpf_ctx->output : stdout;
     if (!bpf_ctx->print_header) {
        time(&t);
        tm = localtime(&t);
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm);
        fprintf(out, "\n[%s] memleak", time_str);
        bpf_ctx->print_header = true;
    }
    fflush(out);
    
    pthread_mutex_lock(&bpf_ctx->stats_mutex);
    if (event->is_alloc) {
        bpf_ctx->stats.alloc_count++;
        bpf_ctx->stats.total_alloc_size += event->size;
    } else {
        bpf_ctx->stats.free_count++;
        bpf_ctx->stats.total_free_size += event->size;
    }
    pthread_mutex_unlock(&bpf_ctx->stats_mutex);
    }

   
}
static void print_stack_trace(struct bpf_ctx *ctx, int stack_id)
{
    __u64 stack_trace[PERF_MAX_STACK_DEPTH] = {};
    FILE *out = ctx->output ? ctx->output : stdout;
    
    if (stack_id < 0) {
        fprintf(out, "  [Invalid stack trace]\n");
        return;
    }

    if (bpf_map_lookup_elem(bpf_map__fd(ctx->skel->maps.stack_traces), 
                           &stack_id, stack_trace) != 0) {
        fprintf(out, "  [Failed to retrieve stack trace]\n");
        return;
    }

    for (int i = 0; i < PERF_MAX_STACK_DEPTH && stack_trace[i]; i++) {
        const struct ksym *ksym = ksyms__map_addr(ctx->ksyms, stack_trace[i]);
        if (ksym) {
            fprintf(out, "    [%2d] %016llx %s+0x%llx\n",
                    i, stack_trace[i], ksym->name, stack_trace[i] - ksym->addr);
        } else {
            fprintf(out, "    [%2d] %016llx [unknown]\n", i, stack_trace[i]);
        }
    }
}
static void print_stats(struct bpf_ctx *ctx)
{
    pthread_mutex_lock(&ctx->stats_mutex);
    printf("\nKMEMLEAK STATS:");
    printf("\tTOTAL alloc %llu free %llu\n",
           ctx->stats.alloc_count, ctx->stats.free_count);
    pthread_mutex_unlock(&ctx->stats_mutex);
}
static void *poll_perf_buffer(void *arg)
{
    struct bpf_ctx *ctx = arg;
    while (!ctx->stop) {
        perf_buffer__poll(ctx->pb, 100);
    }
    return NULL;
}

static int bpf_kmemleak_init(struct prof_dev *dev)
{
    struct bpf_ctx *ctx = calloc(1, sizeof(*ctx));
    int err;
    struct timespec ts;
    struct trace_func_list alloc_funcs, free_funcs;
    struct env *env = dev->env;

    if (parse_class_func_list(env->allocs, &alloc_funcs) != 0) {
        fprintf(stderr, "Invalid --allocs format: %s\n", env->allocs);
        goto failed;
    }
    if (parse_class_func_list(env->frees, &free_funcs) != 0) {
        fprintf(stderr, "Invalid --frees format: %s\n", env->frees);
        goto failed;
    }

    if (!ctx) {
        fprintf(stderr, "Error: Failed to allocate context\n");
        return -1;
    }
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ctx->start_mono_time = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    time(&ctx->start_real_time);
    
    INIT_LIST_HEAD(&ctx->event_queue);
    pthread_mutex_init(&ctx->event_queue_mutex, NULL);
    pthread_cond_init(&ctx->event_queue_cond, NULL);
    ctx->order_thread_stop = false;
    ctx->env = dev->env;
    ctx->leak_reported = false;
    if (dev->env->flamegraph)
        ctx->flamegraph = strdup(dev->env->flamegraph);
    ctx->ksyms = ksyms__load();
    if (!ctx->ksyms) {
        fprintf(stderr, "Error: Failed to load kernel symbols (kallsyms or vmlinux)\n");
        goto failed;
    }

    pthread_mutex_init(&ctx->stats_mutex, NULL);
    memset(&ctx->stats, 0, sizeof(ctx->stats));
    INIT_LIST_HEAD(&ctx->lost_list);

    ctx->skel = bpf_kmemleak_bpf__open();
    if (!ctx->skel) {
        fprintf(stderr, "Error: Failed to open BPF skeleton\n");
        goto failed;
    }
   
    err = bpf_map__set_max_entries(ctx->skel->maps.allocations, 1000000);
    if (err < 0) {
        fprintf(stderr, "Error: Failed to set max entries for allocations map: %s\n", strerror(-err));
        goto failed;
    }

    if (bpf_kmemleak_bpf__load(ctx->skel)) {
        fprintf(stderr, "Error: Failed to load BPF skeleton\n");
        goto failed;
    }

    for (int i = 0; i < alloc_funcs.count; i++) {
        if (strcmp(alloc_funcs.funcs[i].class, "kmem") == 0) {
            struct bpf_link *link = bpf_program__attach_tracepoint(
                ctx->skel->progs.trace_kmalloc,
                alloc_funcs.funcs[i].class,
                alloc_funcs.funcs[i].func   
            );
            if (!link) {
                fprintf(stderr, "Failed to attach alloc tracepoint: %s:%s\n",
                        alloc_funcs.funcs[i].class, alloc_funcs.funcs[i].func);
                goto failed;
            }
        } else if (strcmp(alloc_funcs.funcs[i].class, "kprobe") == 0 || strcmp(alloc_funcs.funcs[i].class, "kprobes") == 0) {
            struct bpf_link *link = bpf_program__attach_kprobe(
                ctx->skel->progs.dummy_kalloc,
                false, 
                alloc_funcs.funcs[i].func
            );
            if (!link) {
                fprintf(stderr, "Failed to attach alloc kprobe: %s\n", alloc_funcs.funcs[i].func);
                goto failed;
            }
        } else {
            fprintf(stderr, "Unknown alloc class: %s\n", alloc_funcs.funcs[i].class);
            goto failed;
        }
    }

    for (int i = 0; i < free_funcs.count; i++) {
        if (strcmp(free_funcs.funcs[i].class, "kmem") == 0) {
            struct bpf_link *link = bpf_program__attach_tracepoint(
                ctx->skel->progs.trace_kfree,
                free_funcs.funcs[i].class,
                free_funcs.funcs[i].func
            );
            if (!link) {
                fprintf(stderr, "Failed to attach free tracepoint: %s:%s\n",
                        free_funcs.funcs[i].class, free_funcs.funcs[i].func);
                goto failed;
            }
        } else if (strcmp(free_funcs.funcs[i].class, "kprobe") == 0 || strcmp(free_funcs.funcs[i].class, "kprobes") == 0) {
            struct bpf_link *link = bpf_program__attach_kprobe(
                ctx->skel->progs.dummy_kfree,
                false,
                free_funcs.funcs[i].func
            );
            if (!link) {
                fprintf(stderr, "Failed to attach free kprobe: %s\n", free_funcs.funcs[i].func);
                goto failed;
            }
        } else {
            fprintf(stderr, "Unknown free class: %s\n", free_funcs.funcs[i].class);
            goto failed;
        }
    }

    ctx->pb = perf_buffer__new(bpf_map__fd(ctx->skel->maps.events), 512,
                              perf_event_callback,perf_event_lost_cb, ctx, NULL);
    if (libbpf_get_error(ctx->pb)) {
        fprintf(stderr, "Error: Failed to create perf buffer\n");
        goto failed;
    }

    if (dev->env->output) {
        ctx->output = fopen(dev->env->output, "w");
        if (!ctx->output) {
            fprintf(stderr, "Error: Failed to open output file %s\n", dev->env->output);
            goto failed;
        }
    }

    ctx->print_header = false;
    ctx->stop = false;
     if (dev->env->time_order) {
        if (pthread_create(&ctx->order_thread, NULL, order_worker, ctx)) {
            fprintf(stderr, "Error: Failed to create order thread\n");
            goto failed;
        }
    }

    if (pthread_create(&ctx->poll_thread, NULL, poll_perf_buffer, ctx)) {
        fprintf(stderr, "Error: Failed to create poll thread\n");
        goto failed;
    }
    if (pthread_create(&ctx->leak_scan_thread, NULL, leak_scan_worker, ctx)) {
        fprintf(stderr, "Error: Failed to create leak scan thread\n");
        goto failed;
    }

    dev->private = ctx;
    return 0;

failed:
    if (ctx) {
        if (ctx->pb) perf_buffer__free(ctx->pb);
        if (ctx->output) fclose(ctx->output);
        if (ctx->skel) bpf_kmemleak_bpf__destroy(ctx->skel);
        pthread_mutex_destroy(&ctx->stats_mutex);
        free(ctx);
    }
    return -1;
}
static void bpf_kmemleak_deinit(struct prof_dev *dev)
{
    struct bpf_ctx *ctx = dev->private;
    struct event_node *node, *tmp;
    if (!ctx) return;
    if (ctx->env->time_order) {
        ctx->order_thread_stop = true;
        pthread_cond_signal(&ctx->event_queue_cond);
        pthread_join(ctx->order_thread, NULL);

        
        pthread_mutex_lock(&ctx->event_queue_mutex);
        list_for_each_entry_safe(node, tmp, &ctx->event_queue, list) {
            list_del(&node->list);
            free(node);
        }
        pthread_mutex_unlock(&ctx->event_queue_mutex);
        
        pthread_mutex_destroy(&ctx->event_queue_mutex);
        pthread_cond_destroy(&ctx->event_queue_cond);
    }

    ctx->stop = true;
    pthread_join(ctx->poll_thread, NULL);

    print_stats(ctx);
     if (dev->env->callchain && !ctx->leak_reported) {
        ctx->leak_reported = true;
        report_leaks(ctx);
    }


    if (ctx->pb) perf_buffer__free(ctx->pb);
    if (ctx->output) fclose(ctx->output);
    if (ctx->ksyms) ksyms__free(ctx->ksyms);
    if (ctx->skel) bpf_kmemleak_bpf__destroy(ctx->skel);
    if (ctx->flamegraph) free(ctx->flamegraph);

    pthread_mutex_destroy(&ctx->stats_mutex);
    pthread_join(ctx->leak_scan_thread, NULL);

    free(ctx);
    dev->private = NULL;
    exit(0);

}

static const char *bpf_kmemleak_desc[] = PROFILER_DESC("bpf:bpf_kmemleak",
    "[OPTION...] --allocs --frees [-g] [--flamegraph] [--time_order] [--output file]",
    "eBPF-based memory leak detection with stack traces", "",
    "BPF-EVENT",
    "    ptr        Memory address",
    "    size       Allocation size",
    "    type       ALLOC/FREE",
    "    pid        Process ID",
    "    comm       Process command name",
    "    stack      Stack trace for allocation", "",
    "EXAMPLES",
    "    "PROGRAME" bpf:bpf_kmemleak --output leaks.txt",
    "    "PROGRAME" bpf:bpf_kmemleak -C 1-4");

static const char *bpf_kmemleak_args[] = PROFILER_ARGV("bpf:bpf_kmemleak",
    PROFILER_ARGV_OPTION,
    PROFILER_ARGV_PROFILER, "allocs","frees","call-graph","flamegraph","time_order","output");

struct monitor bpf_kmemleak = {
    .name = "bpf:bpf_kmemleak",
    .desc = bpf_kmemleak_desc, 
    .argv = bpf_kmemleak_args,
    .pages = 4,
    .init = bpf_kmemleak_init,
    .deinit = bpf_kmemleak_deinit,
};
MONITOR_REGISTER(bpf_kmemleak)