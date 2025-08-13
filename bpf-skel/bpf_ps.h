
#ifndef __BPF_PS_H
#define __BPF_PS_H
#define TASK_COMM_LEN 32 

//state
/* Used in tsk->__state: */
#define TASK_RUNNING			0x00000000
#define TASK_INTERRUPTIBLE		0x00000001
#define TASK_UNINTERRUPTIBLE		0x00000002
#define __TASK_STOPPED			0x00000004
#define __TASK_TRACED			0x00000008
/* Used in tsk->exit_state: */
#define EXIT_DEAD			0x00000010
#define EXIT_ZOMBIE			0x00000020
#define EXIT_TRACE			(EXIT_ZOMBIE | EXIT_DEAD)
/* Used in tsk->__state again: */
#define TASK_PARKED			0x00000040
#define TASK_DEAD			0x00000080
#define TASK_WAKEKILL			0x00000100
#define TASK_WAKING			0x00000200
#define TASK_NOLOAD			0x00000400
#define TASK_NEW			0x00000800
#define TASK_RTLOCK_WAIT		0x00001000
#define TASK_FREEZABLE			0x00002000
#define TASK_FROZEN			0x00008000
#define TASK_STATE_MAX			0x00010000

#define TASK_ANY			(TASK_STATE_MAX-1)

/*
 * DO NOT ADD ANY NEW USERS !
 */
#define TASK_FREEZABLE_UNSAFE		(TASK_FREEZABLE | __TASK_FREEZABLE_UNSAFE)

/* Convenience macros for the sake of set_current_state: */
#define TASK_KILLABLE			(TASK_WAKEKILL | TASK_UNINTERRUPTIBLE)
#define TASK_STOPPED			(TASK_WAKEKILL | __TASK_STOPPED)
#define TASK_TRACED		(TASK_WAKEKILL | __TASK_TRACED)

#define TASK_IDLE			(TASK_UNINTERRUPTIBLE | TASK_NOLOAD)

/* Convenience macros for the sake of wake_up(): */
#define TASK_NORMAL			(TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE)

/* get_task_state(): */
#define TASK_REPORT			(TASK_RUNNING | TASK_INTERRUPTIBLE | \
					 TASK_UNINTERRUPTIBLE | __TASK_STOPPED | \
					 __TASK_TRACED | EXIT_DEAD | EXIT_ZOMBIE | \
					 TASK_PARKED)


#define TASK_REPORT_IDLE  0x80 // kernel 4.14 and later.
#define TASK_REPORT_MAX  0x100 // kernel 4.14 and later.
//thread
#define PF_KTHREAD		0x00200000	/* I am a kernel thread */
//prio
#define MAX_RT_PRIO		100
#define MAX_NICE	19
#define MIN_NICE	-20
#define NICE_WIDTH	(MAX_NICE - MIN_NICE + 1)
#define MAX_PRIO		(MAX_RT_PRIO + NICE_WIDTH)
#define DEFAULT_PRIO		(MAX_RT_PRIO + NICE_WIDTH / 2)
#define PRIO_TO_NICE(prio)	((prio) - DEFAULT_PRIO)
//time
#define HZ 100
#define NSEC_PER_TICK  10000000L

/*
 * Scheduling policies
 */
#define SCHED_NORMAL		0
#define SCHED_FIFO		1
#define SCHED_RR		2
#define SCHED_BATCH		3
/* SCHED_ISO: reserved but not implemented yet */
#define SCHED_IDLE		5

                                    //   TS  SCHED_OTHER
                                    //   FF  SCHED_FIFO
                                    //   RR  SCHED_RR
                                    //   B   SCHED_BATCH
                                    //   ISO SCHED_ISO
                                    //   IDL SCHED_IDLE

                                    

#define SIGHUP		 1
#define SIGINT		 2
#define SIGQUIT		 3
#define SIGILL		 4
#define SIGTRAP		 5
#define SIGABRT		 6
#define SIGBUS		 7
#define SIGFPE		 8
#define SIGKILL		 9
#define SIGUSR1		10
#define SIGSEGV		11
#define SIGUSR2		12
#define SIGPIPE		13
#define SIGALRM		14
#define SIGTERM		15
#define SIGSTKFLT	16
#define SIGCHLD		17
#define SIGCONT		18
#define SIGSTOP		19
#define SIGTSTP		20
#define SIGTTIN		21
#define SIGTTOU		22
#define SIGURG		23
#define SIGXCPU		24
#define SIGXFSZ		25
#define SIGVTALRM	26
#define SIGPROF		27
#define SIGWINCH	28

#define SIGPWR		30
#define SIGSYS		31
#define	SIGUNUSED	31


#define SA_RESTORER	0x04000000

#define MINSIGSTKSZ	2048
#define SIGSTKSZ	8192


typedef struct mapstruct {
  const char *name;
  int num;
} mapstruct;


/* 字段采集config*/
struct field_collection_config {
    __u8 grep_mode;
    __u8 child_pid_mode;
    __u8 pkill_mode;
    __u8 collect_basic;        //  pid, ppid, comm
    __u8 collect_time;         // start_boottime, sum_time, cutime
    __u8 collect_memory;       // rss, total_vm
    __u8 collect_cpu;          // cpu, policy, pri, ni
    __u8 collect_state;        // state, exit_state, flags
    __u8 collect_user;         // uid, ruid, rgid
    __u8 collect_tty;          // tty, tty_pgrp
    __u8 collect_thread;       // tgid, lwp, num_threads
    __u8 collect_extended;     // sid, tpgid, rt_priority, vm_locked
    int pid;
    __u8 only_process; 
};

struct task_info {
    /* id */
    __u32 pid;              
    __u32 ppid;             
    __u32 uid;
    __u32 rgid;
    __u32 ruid;              
    __u32 tgid; 
    bool sid; 
    __u32 tty_pgrp;
    __u32 tpgid;  
    __u32 lwp;
    char  user[16]; 

    /* state */
    __u32 state;            
    __u32 exit_state;
           
    
    /* thread */
    __u32 num_threads;            
    
    /*prio */
    __s32 pri;              
    __s32 ni;


    /* time */
    __u64 start_boottime;  
    __u64 sum_time;
    __u64 start_time; 

    
    /* mem */
    __u64 rss;
    unsigned long total_vm;
    unsigned int policy;
    unsigned int flags;	
    unsigned int cpu;	
    unsigned int rt_priority;


    /* name */
    char comm[TASK_COMM_LEN];
    char tty[TASK_COMM_LEN];  
    bool vm_locked; 

};

#endif