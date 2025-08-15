from PerfProf import PerfProf
from conftest import result_check

def test_bpf_bpf_lsof_port(runtime, memleak_check):
    # 测试 --port 36000 端口过滤
    prof = PerfProf(["bpf:bpf_lsof", "--port", "36000"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_bpf_bpf_lsof_unix_file(runtime, memleak_check):
    # 测试 --unix_file unix域文件过滤
    prof = PerfProf(["bpf:bpf_lsof", "--unix_file"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_bpf_bpf_lsof_tcp_listen(runtime, memleak_check):
    # 测试 --tcp_listen tcp监听状态过滤
    prof = PerfProf(["bpf:bpf_lsof", "--tcp_listen"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_bpf_bpf_lsof_pidof_3934(runtime, memleak_check):
    # 测试 lsof -p 过滤
    prof = PerfProf(["bpf:bpf_lsof", "--pidof", "3934"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_bpf_bpf_lsof_grep_atxt(runtime, memleak_check):
    # 测试 --grep a.txt 路径字段模糊匹配
    prof = PerfProf(["bpf:bpf_lsof", "--grep", "a.txt"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_bpf_bpf_lsof_interval_1000(runtime, memleak_check):
    # 测试周期采集 -i 1000 (每1秒)
    prof = PerfProf(["bpf:bpf_lsof", "-i", "1000"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)

def test_bpf_bpf_lsof_tcp_listen_pidof_3934(runtime, memleak_check):
    # 测试 --tcp_listen 和 --pidof 3934 联合过滤
    prof = PerfProf(["bpf:bpf_lsof", "--tcp_listen", "--pidof", "3934"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
def test_bpf_bpf_lsof_tcp_listen_pidof_3934(runtime, memleak_check):
    # 测试 --unix_file 和 --pidof 3934 联合过滤
    prof = PerfProf(["bpf:bpf_lsof", "--unix_file", "--pidof", "3934"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)
def test_bpf_bpf_lsof_path_proc_swaps(runtime, memleak_check):
    # 测试 --path /proc/swaps 路径过滤
    prof = PerfProf(["bpf:bpf_lsof", "--path", "/proc/swaps"])
    for std, line in prof.run(runtime, memleak_check):
        result_check(std, line, runtime, memleak_check)