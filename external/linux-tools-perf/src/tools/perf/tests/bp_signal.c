
#define __SANE_USERSPACE_TYPES__

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <linux/compiler.h>
#include <linux/hw_breakpoint.h>

#include "tests.h"
#include "debug.h"
#include "perf.h"

static int fd1;
static int fd2;
static int overflows;

__attribute__ ((noinline))
static int test_function(void)
{
	return time(NULL);
}

static void sig_handler(int signum __maybe_unused,
			siginfo_t *oh __maybe_unused,
			void *uc __maybe_unused)
{
	overflows++;

	if (overflows > 10) {
		ioctl(fd1, PERF_EVENT_IOC_DISABLE, 0);
		ioctl(fd2, PERF_EVENT_IOC_DISABLE, 0);
	}
}

static int bp_event(void *fn, int setup_signal)
{
	struct perf_event_attr pe;
	int fd;

	memset(&pe, 0, sizeof(struct perf_event_attr));
	pe.type = PERF_TYPE_BREAKPOINT;
	pe.size = sizeof(struct perf_event_attr);

	pe.config = 0;
	pe.bp_type = HW_BREAKPOINT_X;
	pe.bp_addr = (unsigned long) fn;
	pe.bp_len = sizeof(long);

	pe.sample_period = 1;
	pe.sample_type = PERF_SAMPLE_IP;
	pe.wakeup_events = 1;

	pe.disabled = 1;
	pe.exclude_kernel = 1;
	pe.exclude_hv = 1;

	fd = sys_perf_event_open(&pe, 0, -1, -1, 0);
	if (fd < 0) {
		pr_debug("failed opening event %llx\n", pe.config);
		return TEST_FAIL;
	}

	if (setup_signal) {
		fcntl(fd, F_SETFL, O_RDWR|O_NONBLOCK|O_ASYNC);
		fcntl(fd, F_SETSIG, SIGIO);
		fcntl(fd, F_SETOWN, getpid());
	}

	ioctl(fd, PERF_EVENT_IOC_RESET, 0);

	return fd;
}

static long long bp_count(int fd)
{
	long long count;
	int ret;

	ret = read(fd, &count, sizeof(long long));
	if (ret != sizeof(long long)) {
		pr_debug("failed to read: %d\n", ret);
		return TEST_FAIL;
	}

	return count;
}

int test__bp_signal(void)
{
	struct sigaction sa;
	long long count1, count2;

	
	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_sigaction = (void *) sig_handler;
	sa.sa_flags = SA_SIGINFO;

	if (sigaction(SIGIO, &sa, NULL) < 0) {
		pr_debug("failed setting up signal handler\n");
		return TEST_FAIL;
	}


	fd1 = bp_event(test_function, 1);
	fd2 = bp_event(sig_handler, 0);

	ioctl(fd1, PERF_EVENT_IOC_ENABLE, 0);
	ioctl(fd2, PERF_EVENT_IOC_ENABLE, 0);

	test_function();

	ioctl(fd1, PERF_EVENT_IOC_DISABLE, 0);
	ioctl(fd2, PERF_EVENT_IOC_DISABLE, 0);

	count1 = bp_count(fd1);
	count2 = bp_count(fd2);

	close(fd1);
	close(fd2);

	pr_debug("count1 %lld, count2 %lld, overflow %d\n",
		 count1, count2, overflows);

	if (count1 != 1) {
		if (count1 == 11)
			pr_debug("failed: RF EFLAG recursion issue detected\n");
		else
			pr_debug("failed: wrong count for bp1%lld\n", count1);
	}

	if (overflows != 1)
		pr_debug("failed: wrong overflow hit\n");

	if (count2 != 1)
		pr_debug("failed: wrong count for bp2\n");

	return count1 == 1 && overflows == 1 && count2 == 1 ?
		TEST_OK : TEST_FAIL;
}
