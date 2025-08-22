
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <linux/sysinfo.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <pwd.h>
#include "monitor.h"
#include "bpf-skel/bpf_ps.h"
#include "bpf-skel/bpf_ps.skel.h"
#define PID_HASH_SIZE 65536

struct bpfiter_ctx
{
    struct bpf_ps_bpf *obj;
    struct bpf_link *link;
    int iter_fd;
    FILE *output;
    pthread_t iter_thread;
    volatile bool stop;
    bool print_header;
    __u64 memtotal;
    __u64 uptime;
    struct env *env;
    __u64 btime;
    int output_pids[32768]; // 存储匹配的PID
    int output_pids_count;  // 匹配的PID计数
    int exact_count;        // 精确匹配计数
    int fuzzy_count;
};

struct task_details
{
    char user_str[32];
    char ruser_str[32];
    char comm_str[512];
    char time_str[32];
};

static const mapstruct sigmap[] = {
    {"HUP", SIGHUP},
    {"INT", SIGINT},
    {"QUIT", SIGQUIT},
    {"ILL", SIGILL},
    {"TRAP", SIGTRAP},
    {"ABRT", SIGABRT},
    {"IOT", SIGIOT},
    {"BUS", SIGBUS},
    {"FPE", SIGFPE},
    {"KILL", SIGKILL},
    {"USR1", SIGUSR1},
    {"SEGV", SIGSEGV},
    {"USR2", SIGUSR2},
    {"PIPE", SIGPIPE},
    {"ALRM", SIGALRM},
    {"TERM", SIGTERM},
    {"STKFLT", SIGSTKFLT},
    {"CHLD", SIGCHLD},
    {"CONT", SIGCONT},
    {"STOP", SIGSTOP},
    {"TSTP", SIGTSTP},
    {"TTIN", SIGTTIN},
    {"TTOU", SIGTTOU},
    {"URG", SIGURG},
    {"XCPU", SIGXCPU},
    {"XFSZ", SIGXFSZ},
    {"VTALRM", SIGVTALRM},
    {"PROF", SIGPROF},
    {"WINCH", SIGWINCH},
    {"IO", SIGIO},
    {"POLL", SIGPOLL},
    {"PWR", SIGPWR},
    {"SYS", SIGSYS},
};
#define SIGMAP_SIZE (sizeof(sigmap) / sizeof(sigmap[0]))
void pkill_callback(void *ctx, int cpu, void *data, __u32 size);
static const char *get_task_state(__u32 state, __u32 state_exit);
static char *status(struct task_info *info, const char *state, struct task_details *details);
static const char *sched_policy(struct task_info *info);

static void *run_iterator(void *arg);
static void cleanup_ctx(struct bpfiter_ctx *ctx);
static void get_proc_data(struct task_info *info, struct task_details *details);
static int monitor_ctx_init(struct prof_dev *dev);
const char *lookup_wchan(struct task_info *info);
int parse_signal(const char *sigstr);
int parse_signal(const char *sigstr)
{
    int i;
    char upper[32];

    while (isspace(*sigstr))
        sigstr++;

    if (*sigstr == '-')
        sigstr++;

    if (isdigit((unsigned char)*sigstr))
    {
        int val = atoi(sigstr);
        if (val > 0 && val < _NSIG)
            return val;
        return -1;
    }

    if (!strncasecmp(sigstr, "SIG", 3))
        sigstr += 3;
    for (i = 0; i < (int)sizeof(upper) - 1 && sigstr[i]; i++)
        upper[i] = toupper((unsigned char)sigstr[i]);
    upper[i] = '\0';


    if (!strcmp(upper, "USER1"))
        strcpy(upper, "USR1");
    if (!strcmp(upper, "USER2"))
        strcpy(upper, "USR2");

    // 查表
    for (i = 0; i < SIGMAP_SIZE; i++)
    {
        if (!strcmp(upper, sigmap[i].name))
            return sigmap[i].num;
    }
    return -1;
}
static int monitor_ctx_init(struct prof_dev *dev)
{
    struct bpfiter_ctx *ctx = zalloc(sizeof(*ctx));
    struct sysinfo sys;
    struct env *env = dev->env;
    struct field_collection_config field_config = {0};

    if (!ctx)
        return -1;
    dev->private = ctx;
    ctx->obj = bpf_ps_bpf__open();
    if (!ctx->obj)
        goto free_ctx;
    ctx->output_pids_count = 0;
    ctx->exact_count = 0; // 初始化精确计数器
    ctx->fuzzy_count = 0;
    memset(ctx->output_pids, 0, sizeof(ctx->output_pids));

    field_config.collect_basic = 1;

    if (env->extend || env->aux)
    {
        field_config.collect_time = 1;
        field_config.collect_memory = 1;
        field_config.collect_cpu = 1;
        field_config.collect_state = 1;
        field_config.collect_user = 1;
        field_config.collect_tty = 1;
    }

    if (env->grep)
    {
        field_config.grep_mode = 1;
        field_config.collect_basic = 0;
    }
    else if (env->pidof)
    {
        field_config.child_pid_mode = 1;
        field_config.collect_basic = 0;
    }
    else if (env->pkill_target && env->signal)
    {
        field_config.pkill_mode = 1;
    }
    else if (env->wchan)
    {
        // wchan模式需要更多字段

        field_config.collect_time = 1;
        field_config.collect_memory = 1;
        field_config.collect_cpu = 1;
        field_config.collect_state = 1;
        field_config.collect_thread = 1;
        field_config.collect_user = 1;
    }
    else if (env->details)
    {
        // details模式需要部分字段
        field_config.collect_time = 1;
        field_config.collect_memory = 1;
        field_config.collect_cpu = 1;
        field_config.collect_state = 1;
        field_config.collect_user = 1;
        field_config.collect_tty = 1;
        field_config.collect_thread=1;
    }
    else
    {
        // 默认模式需要基本显示字段
        field_config.collect_time = 1;
        field_config.collect_cpu = 1;
        field_config.collect_user = 1;
        field_config.collect_tty = 1;
    }

    /* 将配置写入rodata */
    memcpy((void *)&ctx->obj->rodata->field_config, &field_config, sizeof(field_config));

    if (bpf_ps_bpf__load(ctx->obj))
        goto free_ctx;

    if (sysinfo(&sys) == 0)
    { // 传递地址
        ctx->memtotal = sys.totalram;
        ctx->uptime = sys.uptime;
        ctx->btime = time(NULL) - ctx->uptime;
    }
    else
    {
        perror("sysinfo failed");
    }
    return 0;
free_ctx:
    free(ctx);
    return -1;
}

const char *lookup_wchan(struct task_info *info)
{
    static __thread char buf[64];
    const char *ret = buf;
    char path[64];
    FILE *wchan_file;

    snprintf(path, sizeof(path), "/proc/%d/wchan", info->pid);
    wchan_file = fopen(path, "r");
    if (!wchan_file)
        return "?";

    if (!fgets(buf, sizeof(buf) - 1, wchan_file))
    {
        fclose(wchan_file);
        return "?";
    }
    fclose(wchan_file);

    buf[strcspn(buf, "\n")] = '\0';
    if (buf[0] == '0' && buf[1] == '\0')
        return "-";

    if (*ret == '.')
        ret++;
    while (*ret == '_')
        ret++;

    return ret;
}

// state
static inline const char *get_task_state(unsigned int tsk_state, unsigned int tsk_exit_state)
{
    unsigned int state = (tsk_state | tsk_exit_state) & TASK_REPORT;

    if ((tsk_state & TASK_IDLE) == TASK_IDLE)
        state = TASK_REPORT_IDLE;

    if (tsk_state & TASK_RTLOCK_WAIT)
        state = TASK_UNINTERRUPTIBLE;

    switch (state)
    {
    case TASK_RUNNING:
        return "R";
    case TASK_INTERRUPTIBLE:
        return "S";
    case TASK_UNINTERRUPTIBLE:
        return "D";
    case __TASK_STOPPED:
        return "T";
    case __TASK_TRACED:
        return "t";
    case TASK_REPORT_IDLE:
        return "I";
    case EXIT_DEAD:
        return "X";
    case EXIT_ZOMBIE:
        return "Z";
    case TASK_PARKED:
        return "P";
    default:
        return "?";
    }
}

static char *status(struct task_info *info, const char *state, struct task_details *details)
{
    static char buf[10] = "   ";
    int end = 0;
    buf[end++] = state[0];
    if (info->ni < 0)
    {
        buf[end++] = '<';
    }
    else if (info->ni > 0)
    {
        buf[end++] = 'N';
    }
    if (info->vm_locked)
    {
        buf[end++] = 'L';
    }
    if (info->sid)
    {
        buf[end++] = 's';
    }

    if (info->num_threads > 1)
    {
        buf[end++] = 'l';
    }
    buf[end] = '\0';
    return buf;
}
static const char *sched_policy(struct task_info *info)
{
    const char *class;
    switch (info->policy)
    {
    case 0:
        class = "TS";
        break;
    case 1:
        class = "FF";
        break;
    case 2:
        class = "RR";
        break;
    case 3:
        class = "B";
        break;
    case 4:
        class = "ISO";
        break;
    case 5:
        class = "IDL";
        break;
    default:
        class = "?";
    }
    return class;
}

/*  /proc  */
static void get_time_str(struct task_info *info, struct task_details *details)
{
    unsigned long total_sec;
    __u32 hours, mins, secs;
    total_sec = info->sum_time / HZ;

    hours = total_sec / 3600;
    mins = (total_sec % 3600) / 60;
    secs = total_sec % 60;
    snprintf(details->time_str, sizeof(details->time_str), "%02u:%02u", hours * 60 + mins, secs);
}
static void get_proc_data(struct task_info *info, struct task_details *details)
{
    char proc_path[32];
    char buf[1024];
    FILE *proc_file;
    size_t len, i;

    // 如果是内核线程，直接用 comm
    if (info->comm[0] == '[' && strchr(info->comm, ']'))
    {
        strncpy(details->comm_str, info->comm, sizeof(details->comm_str) - 1);
        details->comm_str[sizeof(details->comm_str) - 1] = '\0';
    }
    else
    {
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/cmdline", info->pid);
        proc_file = fopen(proc_path, "r");
        if (proc_file)
        {
            len = fread(buf, 1, sizeof(buf) - 1, proc_file);
            fclose(proc_file);
            if (len > 0)
            {
                buf[len] = '\0';
                for (i = 0; i < len - 1; i++)
                {
                    if (buf[i] == '\0')
                        buf[i] = ' ';
                }
                strncpy(details->comm_str, buf, sizeof(details->comm_str) - 1);
                details->comm_str[sizeof(details->comm_str) - 1] = '\0';
            }
            else
            {
                strncpy(details->comm_str, info->comm, sizeof(details->comm_str) - 1);
                details->comm_str[sizeof(details->comm_str) - 1] = '\0';
            }
        }
        else
        {
            strncpy(details->comm_str, info->comm, sizeof(details->comm_str) - 1);
            details->comm_str[sizeof(details->comm_str) - 1] = '\0';
        }
    }
}

static void format_time_info(struct bpfiter_ctx *ctx, struct task_info *info,
                             char *start_ss_str, char *lstart_str, char *etime_str)
{
    time_t now, start_time;
    struct tm *tm, *tm_now;
    unsigned long t;
    unsigned dd, hh, mm, ss;
    char *cp = etime_str;
    int current_year, current_yday;

    // 获取当前时间信息
    now = time(NULL);
    tm_now = localtime(&now);
    current_year = tm_now->tm_year;
    current_yday = tm_now->tm_yday;

    // 初始化输出
    if (start_ss_str)
        strcpy(start_ss_str, "?");
    if (lstart_str)
        strcpy(lstart_str, "?");
    if (etime_str)
        strcpy(etime_str, "?");

    if (!ctx->btime)
        return;

    // 计算启动时间
    start_time = (time_t)(ctx->btime + (info->start_boottime / 1000000000));
    tm = localtime(&start_time);
    if (!tm)
        return;

    // start_ss_str: 根据是否今天决定显示格式
    if (start_ss_str)
    {
        if (tm->tm_year + 1900 == current_year && tm->tm_yday == current_yday)
        {
            // 如果是今天，显示时分秒
            strftime(start_ss_str, 16, "%H:%M:%S", tm);
        }
        else
        {
            // 如果不是今天，显示月日
            strftime(start_ss_str, 16, "%b %d", tm);
        }
    }

    // lstart_str: 完整ctime格式
    if (lstart_str)
    {
        char *ctime_str = ctime(&start_time);
        if (ctime_str)
        {
            size_t len = strlen(ctime_str);
            if (len > 0 && ctime_str[len - 1] == '\n')
                ctime_str[len - 1] = '\0';
            strncpy(lstart_str, ctime_str, 24);
            lstart_str[24] = '\0';
        }
    }

    // etime_str: 运行时长
    if (etime_str)
    {
        t = (unsigned long)(now - start_time);
        ss = t % 60;
        t /= 60;
        mm = t % 60;
        t /= 60;
        hh = t % 24;
        t /= 24;
        dd = t;

        cp = etime_str;
        cp += (dd ? snprintf(cp, 16, "%u-", dd) : 0);
        cp += ((dd || hh) ? snprintf(cp, 16, "%02u:", hh) : 0);
        snprintf(cp, 16, "%02u:%02u", mm, ss);
    }
}

/* 计算百分比的通用函数 */
static void calculate_cpu_mem_percentage(struct bpfiter_ctx *ctx, struct task_details *details,
                                         struct task_info *info, char *cpu_str, char *mem_str)
{
    unsigned long pmem = 0, pcpu = 0;
    unsigned long long seconds;

    // 计算内存百分比
    if (ctx->memtotal > 0)
    {
        pmem = info->rss * 4000ULL * 1024 / ctx->memtotal;
        if (pmem > 999)
            pmem = 999;
    }
    if (mem_str)
    {
        snprintf(mem_str, 16, "%2u.%u", (unsigned)(pmem / 10), (unsigned)(pmem % 10));
    }

    // 计算CPU百分比
    seconds = ctx->uptime - info->start_time / HZ;
    if (seconds > 0)
    {
        pcpu = (info->sum_time * 1000ULL / HZ) / seconds;
        if (pcpu > 999)
            pcpu = 999;
    }
    if (cpu_str)
    {
        snprintf(cpu_str, 16, "%2u.%u", (unsigned)(pcpu / 10), (unsigned)(pcpu % 10));
    }
}

/* 统一的输出格式化函数 */
static void format_task_output(struct bpfiter_ctx *ctx, struct task_info *info,
                               FILE *out, struct task_details details)
{
    const char *state = NULL, *task_state, *policy_str = NULL;
    char start_str[16], lstart_str[32], etime_str[32];
    char mem_str[16], cpu_str[16];
    if (!ctx->env->grep && !ctx->env->pidof && !ctx->env->details)
    {
        calculate_cpu_mem_percentage(ctx, &details, info, cpu_str, mem_str);
        state = get_task_state(info->state, info->exit_state);
        task_state = status(info, state, &details);
        policy_str = sched_policy(info);
        get_time_str(info, &details);
        format_time_info(ctx, info, start_str, lstart_str, etime_str);
    }

    if (ctx->env->wchan)
    {
        const char *wchan_result = lookup_wchan(info);
        char wchan_name[64];
        unsigned int flags;
        struct passwd *pw,*rpw;
        strncpy(wchan_name, wchan_result, sizeof(wchan_name) - 1);
        wchan_name[sizeof(wchan_name) - 1] = '\0';
        pw = getpwuid(info->uid);
        rpw = getpwuid(info->ruid);
        flags = ((unsigned)(info->flags >> 6U) & 0x7U);
        if (pw)
        {
            strncpy(details.user_str, pw->pw_name, sizeof(details.user_str) - 1);
            details.user_str[sizeof(details.user_str) - 1] = '\0';
            if (strlen(details.user_str) > 8)
            {
                details.user_str[7] = '+';
                details.user_str[8] = '\0';
            }
        }
        if (rpw)
        {
            strncpy(details.ruser_str, rpw->pw_name, sizeof(details.ruser_str) - 1);
            details.ruser_str[sizeof(details.ruser_str) - 1] = '\0';
            if (strlen(details.ruser_str) > 8)
            {
                details.ruser_str[7] = '+';
                details.ruser_str[8] = '\0';
            }
        }
        
        if (ctx->print_header)
        {
            ctx->print_header = false;
            fprintf(out, "%-8s  %-6s %-4s  %-8s %-8s %-8s %-8s %-6s    %-4s %-4s     %-3s %-6s %-6s %-6s %-8s %-8s  %-15s  \n",
                        "USER","PSR","UID","RUSER","PID", "PPID", "PGID", 
                        "STARTED", 
                         "SCH", "CLS",
                         "SZ", 
                         "STATE","NLWP","PRI","FLAG", "WCHAN", "COMMAND");
        }

        fprintf(out, " %-8s  %-7d %-3d %-8s %-8d %-8d %-8d  %-8s %-5d %-5s  %-7ld %-5s %-7d  %-5d %-5d  %-15s  %-12s\n",
                details.user_str,info->cpu,info->uid,details.ruser_str,info->pid,info->ppid, info->tpgid,
                start_str,  info->policy,policy_str, info->total_vm, state, info->num_threads,info->pri,flags,wchan_name, details.comm_str);
    }
    else if (ctx->env->details)
    {
        struct passwd *pw = getpwuid(info->uid);
        calculate_cpu_mem_percentage(ctx, &details, info, cpu_str, NULL);
        get_time_str(info, &details);
        format_time_info(ctx, info, start_str, NULL, NULL);
        if (ctx->print_header)
        {
            ctx->print_header = false;
            fprintf(out, "%-7s %-8s  %-8s  %-8s %-8s %-4s   %-5s %-6s %-10s    %-15s  \n",
                        "USER", "PID","PPID", "TID","NUM_THREADS","TTY", "%CPU","START", "TIME", "COMMAND");
        }
        if (pw)
        {
            strncpy(details.user_str, pw->pw_name, sizeof(details.user_str) - 1);
            details.user_str[sizeof(details.user_str) - 1] = '\0';
            if (strlen(details.user_str) > 8)
            {
                details.user_str[7] = '+';
                details.user_str[8] = '\0';
            }
        }
        fprintf(out, " %-8s %-8d %-8d %-8d %-12d %-3s  %-3s %-6s %-8s   %-12s\n",
                details.user_str, info->pid, info->ppid, info->lwp, info->num_threads, info->tty, cpu_str, start_str, details.time_str, details.comm_str);
    
    }
    else if (ctx->env->extend)
    {
        struct passwd *pw = getpwuid(info->uid);
         if (pw)
        {
            strncpy(details.user_str, pw->pw_name, sizeof(details.user_str) - 1);
            details.user_str[sizeof(details.user_str) - 1] = '\0';
            if (strlen(details.user_str) > 8)
            {
                details.user_str[7] = '+';
                details.user_str[8] = '\0';
            }
        }
        if (ctx->print_header)
        {
            ctx->print_header = false;
            fprintf(out, "%-8s %-8s %-8s %-6s %-7s  %-5s  %-5s  %-6s %-8s %-10s %-18s  %-15s %-15s  %-15s   \n",
                        "PID", "CPU", "USER", "RGID", "CLS", "PPID",  "STATE", "PRIO", "NI", "START", "ELAPSED", "ETIME", "COMM", "COMMAND");
        }
        fprintf(out, " %-8d %-6d %-8s  %-8d %-5s  %-5d     %-4s %-5d %-5d %-6s  %-8s  %-8s  %-8s  %-15s\n",
                info->pid, info->cpu, details.user_str, info->rgid,
                policy_str, info->ppid,
                task_state, 39 - info->pri, info->ni,
                start_str, lstart_str, etime_str,
                info->comm, details.comm_str);
    }
    else if (ctx->env->aux)
    {
        struct passwd *pw = getpwuid(info->uid);
        if (pw)
        {
            strncpy(details.user_str, pw->pw_name, sizeof(details.user_str) - 1);
            details.user_str[sizeof(details.user_str) - 1] = '\0';
            if (strlen(details.user_str) > 8)
            {
                details.user_str[7] = '+';
                details.user_str[8] = '\0';
            }
        }
        if (ctx->print_header)
        {
            ctx->print_header = false;
            fprintf(out, "%-8s %-8s %-6s %-6s %-7s  %-8s  %-6s  %-4s %-8s %-8s %-15s \n",
                        "USER","PID", "%CPU", "%MEM", "RSS", "VSIZE", "TTY",  "STATE", "START", "TIME", "COMM");
        }
        fprintf(out, " %-8s %-8d  %-4s %-4s  %-7lld %-7ld %-6s %-4s  %-8s  %-8s   %-15s\n",
                details.user_str, info->pid,

                cpu_str, mem_str, 4 * info->rss, 4*info->total_vm, info->tty, task_state,
                start_str, details.time_str, details.comm_str);
    }
    else
    {
        struct passwd *pw = getpwuid(info->uid);
        if (pw)
        {
            strncpy(details.user_str, pw->pw_name, sizeof(details.user_str) - 1);
            details.user_str[sizeof(details.user_str) - 1] = '\0';
            if (strlen(details.user_str) > 8)
            {
                details.user_str[7] = '+';
                details.user_str[8] = '\0';
            }
        }
        if (ctx->print_header)
        {
            ctx->print_header = false;
            fprintf(out, "%-8s %-8s %-8s %-6s  %-8s  %-6s  %-8s  %-15s \n",
                        "USER","PID","PPID", "%CPU",   "START", "TTY", "TIME", "COMM");
        }
        fprintf(out, " %-8s %-8d %-8d   %-3s    %-3s  %-4s %-4s  %-15s\n",
                details.user_str, info->pid, info->ppid, cpu_str, start_str, info->tty,
                details.time_str, details.comm_str);
    }
}

static int pid_in_array(int *arr, int n, int pid)
{
    for (int i = 0; i < n; i++)
        if (arr[i] == pid)
            return 1;
    return 0;
}
static void *run_iterator(void *arg)
{
    struct bpfiter_ctx *ctx = arg;
    FILE *out = ctx->output ? ctx->output : stdout;
    struct task_info info;
    ssize_t len;
    bool iteration_completed = false;
    int iteration_count = 0;
    static int child_header_printed = 0;

    while (!ctx->stop && iteration_count < 1)
    {
        len = read(ctx->iter_fd, &info, sizeof(info));
        if (len < 0)
        {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            perror("read iter_fd");
            break;
        }
        else if (len == 0)
        {
            iteration_completed = true;
        }
        else if (len == sizeof(info))
        {

            struct task_details details;
            get_proc_data(&info, &details);
            if (ctx->env->grep)
            {
                char cmdline[512] = "";
                char path[64];
                FILE *f;
                size_t len2, i;
                int pid = info.pid;
                int matched = 0;

                snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
                f = fopen(path, "r");
                if (f)
                {
                    len2 = fread(cmdline, 1, sizeof(cmdline) - 1, f);
                    fclose(f);
                    if (len2 > 0)
                    {
                        cmdline[len2] = '\0';
                        for (i = 0; i < len2 - 1; i++)
                            if (cmdline[i] == '\0')
                                cmdline[i] = ' ';
                    }
                }

                if (ctx->env->match == 2)
                {
                    // pgrep -la 模式：cmdline模糊匹配
                    if (strstr(cmdline, ctx->env->grep) != NULL)
                        matched = 1;

                    if (matched)
                    {
                        if (pid == getpid())
                            continue;
                        if (!pid_in_array(ctx->output_pids, ctx->output_pids_count, pid))
                        {
                            ctx->output_pids[ctx->output_pids_count++] = pid;

                            if (ctx->print_header)
                            {
                                ctx->print_header = false;
                                fprintf(out, "%-8s %s\n", "PID", "CMDLINE");
                            }
                            fprintf(out, "%-8d %s\n", pid, cmdline);
                        }
                    }
                }
                else
                {
                    int exact_match = 0;
                    int fuzzy_match = 0;

                    if (!ctx->env->match)
                    {
                        // 这里保持原精确匹配comm逻辑
                        if (strcmp(info.comm, ctx->env->grep) == 0 ||
                            strncmp(info.comm, ctx->env->grep, strlen(ctx->env->grep)) == 0)
                        {
                            exact_match = 1;
                            ctx->exact_count++;
                        }
                    }
                    else
                    {
                        // match 非0时 匹配cmdline
                        if (strstr(cmdline, ctx->env->grep) != NULL)
                        {
                            fuzzy_match = 1;
                            ctx->fuzzy_count++;
                        }
                    }

                    if (exact_match || fuzzy_match)
                    {
                        if (pid == getpid())
                            continue;
                        if (!pid_in_array(ctx->output_pids, ctx->output_pids_count, pid))
                        {
                            ctx->output_pids[ctx->output_pids_count++] = pid;

                            if (ctx->print_header)
                            {
                                ctx->print_header = false;
                                fprintf(out, "%-8s %-8s %-15s %-15s %-10s\n",
                                        "PID", "COMM", "EXACT_MATCH", "FUZZY_MATCH", "TOTAL");
                            }

                            fprintf(out, "%-10d %-13s %-15d %-15d %-8d\n",
                                    pid,
                                    info.comm,
                                    exact_match ? 1 : 0,
                                    fuzzy_match ? 1 : 0,
                                    ctx->output_pids_count);
                        }
                    }
                }
                continue;
            }
            // ---- pkill 逻辑 ----
            if (ctx->env->pkill_target)
            {
                char cmdline[512] = "";
                char path[64];
                FILE *f;
                size_t len2, i;
                int match = 0;
                int pid = info.pid;
                snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
                f = fopen(path, "r");
                if (f)
                {
                    len2 = fread(cmdline, 1, sizeof(cmdline) - 1, f);
                    fclose(f);
                    if (len2 > 0)
                    {
                        cmdline[len2] = '\0';
                        for (i = 0; i < len2 - 1; i++)
                            if (cmdline[i] == '\0')
                                cmdline[i] = ' ';
                    }
                }
                if (ctx->env->match)
                {
                    if (strstr(info.comm, ctx->env->pkill_target) ||
                        strstr(cmdline, ctx->env->pkill_target))
                        match = 1;
                }
                else
                {
                    if (strcmp(info.comm, ctx->env->pkill_target) == 0)
                        match = 1;
                }
                if (match)
                {
                    int sig = SIGTERM;
                    if (ctx->env->signal)
                        sig = parse_signal(ctx->env->signal);
                    kill(pid, sig);
                    fprintf(stderr, "kill %d (%s)\n", pid, info.comm);
                }
                continue;
            }

            if (ctx->env->pidof)
            {
                if (info.ppid == ctx->env->pidof)
                {
                    if (!child_header_printed)
                    {
                        fprintf(out, "%-8s\n", "PID");
                        child_header_printed = 1;
                    }
                    fprintf(out, "%d\n", info.pid);
                }
                continue;
            }

            format_task_output(ctx, &info, out, details);
            fflush(out);
        }

        if (iteration_completed)
        {
            iteration_count++;

            cleanup_ctx(ctx); // 主动清理资源
            exit(0);          // 退出线程
        }
    }
    return NULL;
}

/* clean */
static void cleanup_ctx(struct bpfiter_ctx *ctx)
{
    if (!ctx)
        return;

    if (ctx->output)
    {
        fclose(ctx->output);
        ctx->output = NULL;
    }
    if (ctx->iter_fd >= 0)
    {
        close(ctx->iter_fd);
        ctx->iter_fd = -1;
    }
    if (ctx->link)
    {
        bpf_link__destroy(ctx->link);
        ctx->link = NULL;
    }

    if (ctx->obj)
    {
        bpf_ps_bpf__destroy(ctx->obj);
        ctx->obj = NULL;
    }
    free(ctx);
}

/* ebpf */
static int bpf_ps_init(struct prof_dev *dev)
{
    struct bpfiter_ctx *ctx;
    if (monitor_ctx_init(dev) < 0)
        return -1;
    ctx = dev->private;
    if (!ctx->print_header)
        ctx->print_header = true;
    return 0;
}

static int bpf_ps_filter(struct prof_dev *dev)
{
    struct bpfiter_ctx *ctx = dev->private;
    struct env *env = dev->env;

    ctx->env = env;
    ctx->link = bpf_program__attach_iter(ctx->obj->progs.dump_task_info, NULL);
    if (libbpf_get_error(ctx->link))
    {
        fprintf(stderr, "Failed to attach iterator\n");
        goto error;
    }

    /* 创建迭代器FD */
    ctx->iter_fd = bpf_iter_create(bpf_link__fd(ctx->link));
    if (ctx->iter_fd < 0)
    {
        fprintf(stderr, "Failed to create iterator\n");
        goto error;
    }

    if (dev->env->output2)
    {
        ctx->output = fopen(dev->env->output2, "w");
        if (!ctx->output)
        {
            fprintf(stderr, "Failed to open output file %s\n", dev->env->output2);
            goto error;
        }
    }

    /* 启动迭代器线程 */
    ctx->stop = false;
    if (pthread_create(&ctx->iter_thread, NULL, run_iterator, ctx))
    {
        fprintf(stderr, "Failed to create iterator thread\n");
        goto error;
    }

    return 0;

error:
    cleanup_ctx(ctx);
    return -1;
}

static void bpf_ps_interval(struct prof_dev *dev)
{
    struct bpfiter_ctx *ctx = dev->private;
    FILE *out = ctx->output ? ctx->output : stdout;
    // 触发迭代器运行
    if (ctx->iter_fd >= 0)
    {
        char buf[4096];
        ssize_t len;

        lseek(ctx->iter_fd, 0, SEEK_SET);

        // 读取迭代器数据
        while ((len = read(ctx->iter_fd, buf, sizeof(buf))))
        {
            if (len < 0)
            {
                if (errno == EAGAIN || errno == EINTR)
                    continue;
                perror("read iter_fd");
                break;
            }
        }
    }

    fflush(out);
}

static void bpf_ps_deinit(struct prof_dev *dev)
{
    struct bpfiter_ctx *ctx = dev->private;
    if (!ctx)
        return;

    ctx->stop = true;
    pthread_join(ctx->iter_thread, NULL);
    cleanup_ctx(ctx);
    dev->private = NULL;
}

static const char *bpf_ps_desc[] = PROFILER_DESC("bpf:bpf_ps",
                                                 "[OPTION...] [--wchan] [--aux]  [--extend] [--details]  [--grep] [--pidof] [--signal]  [--pkill_target][--match][--output2 file]",
                                                "Implement ps functionality using eBPF iterator, printing process information.", "",
                                                 "BPF-EVENT",
                                                 "    pid      Process ID",
                                                 "    user     User name",
                                                 "    state    Process state (R, S, D, etc.)",
                                                 "    comm     Process command name or path",
                                                 "    time     CPU time consumed (HH:MM:SS)",
                                                 "    start    Process start time (HH:MM or MMM DD)", "",
                                                 "EXAMPLES",
                                                 "    " PROGRAME " bpf:bpf_ps --wchan",
                                                 "    " PROGRAME " bpf:bpf_ps --extend",
                                                 "    " PROGRAME " bpf:bpf_ps --details",
                                                 "    " PROGRAME " bpf:bpf_ps --grep comm",
                                                 "    " PROGRAME " bpf:bpf_ps --pidof target_pid",
                                                 "    " PROGRAME " bpf:bpf_ps --signal signal_num --match mode --pkill_target comm");

static const char *bpf_ps_args[] = PROFILER_ARGV("bpf:bpf_ps",
                                                 PROFILER_ARGV_OPTION,
                                                 PROFILER_ARGV_PROFILER, "wchan", "aux", "extend", "details", "grep", "pidof",  "signal", "pkill_target", "match", "output2");

struct monitor bpf_ps = {
    .name = "bpf:bpf_ps",
    .desc = bpf_ps_desc,
    .argv = bpf_ps_args,
    .pages = 4,
    .init = bpf_ps_init,
    .filter = bpf_ps_filter,
    .deinit = bpf_ps_deinit,
    .interval = bpf_ps_interval,
};

MONITOR_REGISTER(bpf_ps)