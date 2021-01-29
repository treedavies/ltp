// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2019 FUJITSU LIMITED. All rights reserved.
 * Author: Yang Xu <xuyang2018.jy@cn.fujitsu.com>
 *
 * Test PR_GET_SECCOMP and PR_SET_SECCOMP of prctl(2).
 * 1) If PR_SET_SECCOMP sets the SECCOMP_MODE_STRICT for the calling thread,
 *    the only system call that the thread is permitted to make are read(2),
 *    write(2),_exit(2)(but not exit_group(2)), and sigreturn(2).  Other
 *    system calls result in the delivery of a SIGKILL signal. This operation
 *    is available only if the kernel is configured with CONFIG_SECCOMP enabled.
 * 2) If PR_SET_SECCOMP sets the SECCOMP_MODE_FILTER for the calling thread,
 *    the system calls allowed are defined by a pointer to a Berkeley Packet
 *    Filter. Other system calls result int the delivery of a SIGSYS signal
 *    with SECCOMP_RET_KILL. The SECCOMP_SET_MODE_FILTER operation is available
 *    only if the kernel is configured with CONFIG_SECCOMP_FILTER enabled.
 * 3) If SECCOMP_MODE_FILTER filters permit fork(2), then the seccomp mode
 *    is inherited by children created by fork(2).
 */

#include <errno.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <linux/filter.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include "tst_test.h"
#include "lapi/syscalls.h"
#include "lapi/prctl.h"
#include "config.h"
#include "lapi/seccomp.h"

#define FNAME "filename"

static const struct sock_filter  strict_filter[] = {
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof (struct seccomp_data, nr))),

	BPF_JUMP(BPF_JMP | BPF_JEQ, __NR_seccomp, 6, 0),
	BPF_JUMP(BPF_JMP | BPF_JEQ, __NR_close, 5, 0),
	BPF_JUMP(BPF_JMP | BPF_JEQ, __NR_exit,  4, 0),
	BPF_JUMP(BPF_JMP | BPF_JEQ, __NR_wait4, 3, 0),
	BPF_JUMP(BPF_JMP | BPF_JEQ, __NR_write, 2, 0),
	BPF_JUMP(BPF_JMP | BPF_JEQ, __NR_clone, 1, 0),

	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
};

static const struct sock_filter  strict_filter_two[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof (struct seccomp_data, nr))),

    BPF_JUMP(BPF_JMP | BPF_JEQ, __NR_seccomp, 6, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ, __NR_close, 5, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ, __NR_exit,  4, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ, __NR_wait4, 3, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ, __NR_write, 2, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ, __NR_clone, 1, 0),

    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
};


static const struct sock_fprog  strict = {
	.len = (unsigned short)ARRAY_SIZE(strict_filter),
	.filter = (struct sock_filter *)strict_filter
};

static const struct sock_fprog  strict_two = {
    .len = (unsigned short)ARRAY_SIZE(strict_filter_two),
    .filter = (struct sock_filter *)strict_filter
};


static void check_filter_mode(void);
static void check_filter_mode_inherit(void);

static struct tcase {
	void (*func_check)();
	int pass_flag;
	int val;
	int exp_signal;
	char *message;
} tcases[] = {
	{check_filter_mode_inherit, 1, 1, SIGSYS,
	"SECCOMP_MODE_FILTER doestn't permit GET_SECCOMP call"},
};

static void check_filter_mode_inherit(void)
{
	int i;
	for (i = 0; i < 10000000; i++){ i+=i; }

	tst_res(TCONF, "Child proc says hi");
	exit(0);
}


static void verify_seccomp_tsync(unsigned int n)
{
	int pid;
	int status;
	struct tcase *tc = &tcases[n];

	tst_res(TINFO,"%d: __NR_seccomp syscall number", __NR_seccomp);
	tst_res(TINFO,"%d: SECCOMP_MODE_FILTER  OP number", SECCOMP_MODE_FILTER);
	tst_res(TINFO,"%d: SECCOMP_FILTER_FLAG_TSYNC  FLAG number", SECCOMP_FILTER_FLAG_TSYNC);

	/* TST_RET:0  errno:0 */	
	TEST(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
	if (TST_RET == 0)
		tst_res(TPASS,"PR_GET_NO_NEW_PRIVS: %d %d", TST_RET, errno);
	else
		tst_res(TFAIL,"PR_GET_NO_NEW_PRIVS: %d %d", TST_RET, errno);

	TEST(tst_syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &strict));
	if (TST_RET == 0)
    	tst_res(TPASS,"SECCOMP_SET_MODE_FILTER 1: %d %d", TST_RET, errno);
	else
    	tst_res(TFAIL,"SECCOMP_SET_MODE_FILTER 1: %d %d", TST_RET, errno);


	pid = SAFE_FORK();
	if (pid == 0) {
		tc->func_check();
	} else {
		tst_res(TCONF,"Parent says hi");

		TEST(tst_syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &strict_two));
		if (TST_RET == 0)
    		tst_res(TPASS,"SECCOMP_MODE_FILTER Filter 2 with SECCOMP_FILTER_FLAG_TSYNC: %d %d", TST_RET, errno);
		else
    		tst_res(TFAIL,"SECCOMP_MODE_FILTER Filter 2 with SECCOMP_FILTER_FLAG_TSYNC: %d %d", TST_RET, errno);

		SAFE_WAITPID(pid, &status, 0);
		if (WIFSIGNALED(status) && WTERMSIG(status) == tc->exp_signal) {
			if (tc->pass_flag)
				tst_res(TPASS, "%s", tc->message);
			else
				tst_res(TFAIL, "%s", tc->message);
			return;
		}

		if (tc->pass_flag == 2)
			tst_res(TFAIL,
				"SECCOMP_MODE_FILTER permits exit() unexpectedly");
	}
}

static void setup(void)
{
	TEST(prctl(PR_GET_SECCOMP));
	if (TST_RET == 0) {
		tst_res(TINFO, "kernel support PR_GET/SET_SECCOMP");
		return;
	}

	if (TST_ERR == EINVAL)
		tst_brk(TCONF, "kernel doesn't support PR_GET/SET_SECCOMP");

	tst_brk(TBROK | TTERRNO,
		"current environment doesn't permit PR_GET/SET_SECCOMP");
}

static struct tst_test test = {
	.setup = setup,
	.test = verify_seccomp_tsync,
	.tcnt = ARRAY_SIZE(tcases),
	.forks_child = 1,
	.needs_tmpdir = 1,
	.needs_root = 1,
};
