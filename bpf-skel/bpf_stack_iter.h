#ifndef __BPF_STACK_ITER_H
#define __BPF_STACK_ITER_H

#define TASK_COMM_LEN 16

struct task_info {
    unsigned int pid;
    char comm[TASK_COMM_LEN];
    long state;
};

#endif