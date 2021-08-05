#!/usr/bin/python

from bcc import BPF
from time import sleep
from time import sleep, strftime
from bcc.syscall import syscall_name, syscalls
import argparse


parser = argparse.ArgumentParser(
    description="Summarize syscall counts by pid")
parser.add_argument("-p", "--pid", type=int, help="trace only this pid")
args = parser.parse_args()

program = ""

if args.pid:
    program = ("#define FILTER_PID %d\n" % args.pid)

program += """
BPF_HASH(data, u32, u64);

TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    #ifdef FILTER_PID
    if (pid_tgid >> 32 != FILTER_PID)
        return 0;
    #endif
    
    u32 key = args->id;

    u64 *val, zero = 0;
    val = data.lookup_or_try_init(&key, &zero);
    if (val) {
        ++(*val);
    }
    return 0;
}
"""

bpf = BPF(text=program)

# header
print("Tracing... Hit Ctrl-C to end.")

def print_count_stats():
	data = bpf["data"]
	print("[%s]" % strftime("%H:%M:%S"))
	print("%-22s %8s" % ("PID    COMM", "COUNT"))
	for k, v in sorted(data.items(), key=lambda kv: -kv[1].value):
		if k.value == 0xFFFFFFFF:
			continue    # happens occasionally, we don't need it
		print("%-22s %8d" % (syscall_name(k.value), v.value))
	print("")
	data.clear()


# trace until Ctrl-C
try:
	sleep(99999999)
except KeyboardInterrupt:
	print_count_stats()