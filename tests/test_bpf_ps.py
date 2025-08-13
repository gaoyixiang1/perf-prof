#!/usr/bin/env python3

from PerfProf import PerfProf
from conftest import result_check

def test_bpf_bpf_ps_extend(runtime, memleak_check):
    prof = PerfProf(["bpf:bpf_ps", "--extend", "-i", "1000"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_bpf_bpf_ps_i(runtime, memleak_check):
    prof = PerfProf(["bpf:bpf_ps", "-i", "1000"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_bpf_bpf_ps_details(runtime, memleak_check):
    prof = PerfProf(["bpf:bpf_ps", "-i", "1000", "--details"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_bpf_bpf_ps_aux(runtime, memleak_check):
    prof = PerfProf(["bpf:bpf_ps", "-i", "1000", "--aux"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_bpf_bpf_ps_wchan(runtime, memleak_check):
    prof = PerfProf(["bpf:bpf_ps", "-i", "1000", "--wchan"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_bpf_bpf_ps_grep_sh(runtime, memleak_check):
    prof = PerfProf(["bpf:bpf_ps", "--grep", "sh"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_bpf_bpf_ps_match0_grep_sh(runtime, memleak_check):
    prof = PerfProf(["bpf:bpf_ps", "--match", "0", "--grep", "sh"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_bpf_bpf_ps_match1_grep_sh(runtime, memleak_check):
    prof = PerfProf(["bpf:bpf_ps", "--match", "1", "--grep", "sh"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_bpf_bpf_ps_match0_pidof_3934(runtime, memleak_check):
    prof = PerfProf(["bpf:bpf_ps", "--match", "0", "--pidof", "3934"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_bpf_bpf_ps_match0_signal9_pkill_target_bas(runtime, memleak_check):
    prof = PerfProf(["bpf:bpf_ps", "--match", "0", "--signal", "9", "--pkill_target", "bas"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)