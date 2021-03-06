// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2016 Linux Test Project
 */

#include <stdlib.h>
#include <sys/mount.h>
#include <stdint.h>

#include "tst_test.h"

static void do_test(void)
{
	int fd;
	const char *dev;
	char block_dev[100];
	uint64_t ltp_dev_size;

	dev = tst_device->dev;
	if (!dev)
		tst_brk(TCONF, "Failed to acquire test device");

	SAFE_MKFS(dev, "ext2", NULL, NULL);

	fd = SAFE_OPEN(dev, O_RDONLY);
	SAFE_IOCTL(fd, BLKGETSIZE64, &ltp_dev_size);
	SAFE_CLOSE(fd);

	if (ltp_dev_size/1024/1024 == 300)
		tst_res(TPASS, "Got expected device size");
	else
		tst_res(TFAIL, "Got unexpected device size");

	tst_find_backing_dev("/boot", block_dev);
	tst_res(TPASS, "/boot belongs to %s block dev", block_dev);
	tst_find_backing_dev("/", block_dev);
	tst_res(TPASS, "/ belongs to %s block dev", block_dev);
	tst_find_backing_dev("/tmp", block_dev);
	tst_find_backing_dev("/boot/xuyang", block_dev);
}

static struct tst_test test = {
	.needs_device = 1,
	.dev_min_size = 300,
	.test_all = do_test,
};
