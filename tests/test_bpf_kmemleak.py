#!/usr/bin/env python3

import pytest
from PerfProf import PerfProf
from conftest import result_check



@pytest.fixture(scope="session")
def runtime():
    return 5  


@pytest.fixture(scope="session")
def memleak_check():
    return 1  


def test_kmemleak_kmalloc(runtime, memleak_check):
    kmemleak = PerfProf(['bpf:bpf_kmemleak',
                        '--allocs', 'kmem:kmalloc',
                        '--frees', 'kmem:kfree',
                         '-g'])
    for std, line in kmemleak.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)


def test_kmemleak_userspace_ftrace_filter(runtime, memleak_check):
    kmemleak = PerfProf(['bpf:bpf_kmemleak',
                        '--allocs', 'kprobes:__kmalloc_node',
                        '--frees', 'kmem:kfree',
                         '-g'])
    for std, line in kmemleak.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)


def test_kmemleak_kmem_cache_alloc(runtime, memleak_check):
    kmemleak = PerfProf(['bpf:bpf_kmemleak',
                        '--allocs', 'kmem:kmem_cache_alloc',
                        '--frees', 'kmem:kmem_cache_free',
                        '-g'])
    for std, line in kmemleak.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)


def test_kmemleak_mm_page_alloc(runtime, memleak_check):

    kmemleak = PerfProf(['bpf:bpf_kmemleak',
                        '--allocs', 'kmem:mm_page_alloc',
                        '--frees', 'kmem:mm_page_free',
                         '--time_order'])
    for std, line in kmemleak.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)


def test_kmemprof_percpu_alloc(runtime, memleak_check):
    kmemleak = PerfProf(['bpf:bpf_kmemleak',
                        '--allocs', 'kprobes:pcpu_alloc',
                        '--frees', 'kprobes:free_percpu',
                        '--time_order'])
    for std, line in kmemleak.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)