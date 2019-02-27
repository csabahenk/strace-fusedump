/*
 * Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 * Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 * Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 * Copyright (c) 1996-1999 Wichert Akkerman <wichert@cistron.nl>
 * Copyright (c) 1999-2018 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "defs.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/uio.h>

extern int fuse_dumpfd;
static char *fuse_dumpbuf = NULL;
static size_t fuse_dumpbufsize = 8192;

static void
fuse_initdumpbuf(size_t size)
{
	if (!fuse_dumpbuf)
		fuse_dumpbuf = xmalloc(fuse_dumpbufsize);
	if (size > fuse_dumpbufsize) {
		fuse_dumpbuf = xreallocarray(fuse_dumpbuf, 1, size);
		fuse_dumpbufsize = size;
	}
}

static int
fuse_check(struct tcb *tcp, int *is_fuse)
{
	struct stat st;
	char ppath[128];
	int rv;

	if (*is_fuse >= 0)
		return *is_fuse;
	if (fuse_dumpfd == -1) {
		*is_fuse = 0;

		return 0;
	}

	snprintf(ppath, sizeof(ppath), "/proc/%d/fd/%ld", tcp->pid,
		 tcp->u_arg[0]);
	rv = stat(ppath, &st);
	*is_fuse = (rv == 0 && st.st_rdev == 0xae5 /* makedev(10, 229) */ );

	return *is_fuse;
}

static void
fuse_printmark(struct tcb *tcp, char mark, int *is_fuse)
{
	if (!fuse_check(tcp, is_fuse))
		return;

	if (write(fuse_dumpfd, &mark, 1) != 1)
		error_msg_and_die("cannot write to fuse dumpfile: %s",
				  strerror(errno));
}

static void
fuse_dumpio(struct tcb *tcp, long addr, size_t size, int *is_fuse)
{
	if (!fuse_check(tcp, is_fuse))
		return;

	fuse_initdumpbuf(size);

	if (umoven(tcp, addr, size, fuse_dumpbuf))
		error_msg_and_die("cannot read data from %#" PRIx64,
				  addr);
	if (write(fuse_dumpfd, fuse_dumpbuf, size) != (ssize_t)size)
		error_msg_and_die("cannot write to fuse dumpfile: %s",
				  strerror(errno));
}

SYS_FUNC(read)
{
	int is_fuse = -1;

	if (entering(tcp)) {
		printfd(tcp, tcp->u_arg[0]);
		tprints(", ");
	} else {
		if (syserror(tcp))
			printaddr(tcp->u_arg[1]);
		else {
			printstrn(tcp, tcp->u_arg[1], tcp->u_rval);
			fuse_printmark(tcp, 'R', &is_fuse);
			fuse_dumpio(tcp, tcp->u_arg[1], tcp->u_rval, &is_fuse);
		}
		tprintf(", %" PRI_klu, tcp->u_arg[2]);
	}
	return 0;
}

SYS_FUNC(write)
{
	int is_fuse = -1;

	printfd(tcp, tcp->u_arg[0]);
	tprints(", ");
	printstrn(tcp, tcp->u_arg[1], tcp->u_arg[2]);
	fuse_printmark(tcp, 'W', &is_fuse);
	fuse_dumpio(tcp, tcp->u_arg[1], tcp->u_arg[2], &is_fuse);
	tprintf(", %" PRI_klu, tcp->u_arg[2]);

	return RVAL_DECODED;
}

struct print_iovec_config {
	enum iov_decode decode_iov;
	kernel_ulong_t data_size;
	int *is_fuse;
};

static bool
print_iovec(struct tcb *tcp, void *elem_buf, size_t elem_size, void *data)
{
	const kernel_ulong_t *iov;
	kernel_ulong_t iov_buf[2], len;
	struct print_iovec_config *c = data;

	if (elem_size < sizeof(iov_buf)) {
		iov_buf[0] = ((unsigned int *) elem_buf)[0];
		iov_buf[1] = ((unsigned int *) elem_buf)[1];
		iov = iov_buf;
	} else {
		iov = elem_buf;
	}

	tprints("{iov_base=");

	len = iov[1];

	switch (c->decode_iov) {
		case IOV_DECODE_STR:
			if (len > c->data_size)
				len = c->data_size;
			if (c->data_size != (kernel_ulong_t) -1)
				c->data_size -= len;
			printstrn(tcp, iov[0], len);
			fuse_dumpio(tcp, iov[0], len, c->is_fuse);
			break;
		case IOV_DECODE_NETLINK:
			if (len > c->data_size)
				len = c->data_size;
			if (c->data_size != (kernel_ulong_t) -1)
				c->data_size -= len;
			/* assume that the descriptor is 1st syscall argument */
			decode_netlink(tcp, tcp->u_arg[0], iov[0], len);
			break;
		default:
			printaddr(iov[0]);
			break;
	}

	tprintf(", iov_len=%" PRI_klu "}", iov[1]);

	return true;
}

static void
tprint_iov_upto_fuse(struct tcb *const tcp, const kernel_ulong_t len,
		     const kernel_ulong_t addr,
		     const enum iov_decode decode_iov,
		     const kernel_ulong_t data_size, int *is_fuse)
{
	kernel_ulong_t iov[2];
	struct print_iovec_config config = {
		.decode_iov = decode_iov, .data_size = data_size, .is_fuse = is_fuse
	};

	print_array(tcp, addr, len, iov, current_wordsize * 2,
		    tfetch_mem_ignore_syserror, print_iovec, &config);
}

/*
 * data_size limits the cumulative size of printed data.
 * Example: recvmsg returing a short read.
 */
void
tprint_iov_upto(struct tcb *const tcp, const kernel_ulong_t len,
		const kernel_ulong_t addr, const enum iov_decode decode_iov,
		const kernel_ulong_t data_size)
{
	int is_fuse = 0;

	tprint_iov_upto_fuse(tcp, len, addr, decode_iov, data_size,
			     &is_fuse);
}

SYS_FUNC(readv)
{
	int is_fuse = -1;

	if (entering(tcp)) {
		printfd(tcp, tcp->u_arg[0]);
		tprints(", ");
	} else {
		fuse_printmark(tcp, 'R', &is_fuse);
		tprint_iov_upto_fuse(tcp, tcp->u_arg[2], tcp->u_arg[1],
				     syserror(tcp) ? IOV_DECODE_ADDR :
				     IOV_DECODE_STR, tcp->u_rval, &is_fuse);
		tprintf(", %" PRI_klu, tcp->u_arg[2]);
	}
	return 0;
}

SYS_FUNC(writev)
{
	int is_fuse = -1;

	printfd(tcp, tcp->u_arg[0]);
	tprints(", ");
	fuse_printmark(tcp, 'W', &is_fuse);
	tprint_iov_upto_fuse(tcp, tcp->u_arg[2], tcp->u_arg[1],
			     IOV_DECODE_STR, -1, &is_fuse);
	tprintf(", %" PRI_klu, tcp->u_arg[2]);

	return RVAL_DECODED;
}

SYS_FUNC(pread)
{
	if (entering(tcp)) {
		printfd(tcp, tcp->u_arg[0]);
		tprints(", ");
	} else {
		if (syserror(tcp))
			printaddr(tcp->u_arg[1]);
		else
			printstrn(tcp, tcp->u_arg[1], tcp->u_rval);
		tprintf(", %" PRI_klu ", ", tcp->u_arg[2]);
		printllval(tcp, "%lld", 3);
	}
	return 0;
}

SYS_FUNC(pwrite)
{
	printfd(tcp, tcp->u_arg[0]);
	tprints(", ");
	printstrn(tcp, tcp->u_arg[1], tcp->u_arg[2]);
	tprintf(", %" PRI_klu ", ", tcp->u_arg[2]);
	printllval(tcp, "%lld", 3);

	return RVAL_DECODED;
}

static void
print_lld_from_low_high_val(struct tcb *tcp, int arg)
{
#if SIZEOF_KERNEL_LONG_T > 4
# ifndef current_klongsize
	if (current_klongsize < SIZEOF_KERNEL_LONG_T) {
		tprintf("%" PRI_kld, (tcp->u_arg[arg + 1] << 32)
			       | tcp->u_arg[arg]);
	} else
# endif /* !current_klongsize */
	{
		tprintf("%" PRI_kld, tcp->u_arg[arg]);
	}
#else /* SIZEOF_KERNEL_LONG_T == 4 */
	tprintf("%lld",
		  ((long long) tcp->u_arg[arg + 1] << 32)
		| ((long long) tcp->u_arg[arg]));
#endif
}

#include "xlat/rwf_flags.h"

static int
do_preadv(struct tcb *tcp, const int flags_arg)
{
	if (entering(tcp)) {
		printfd(tcp, tcp->u_arg[0]);
		tprints(", ");
	} else {
		kernel_ulong_t len =
			truncate_kulong_to_current_wordsize(tcp->u_arg[2]);

		tprint_iov_upto(tcp, len, tcp->u_arg[1],
				syserror(tcp) ? IOV_DECODE_ADDR :
				IOV_DECODE_STR, tcp->u_rval);
		tprintf(", %" PRI_klu ", ", len);
		print_lld_from_low_high_val(tcp, 3);
		if (flags_arg >= 0) {
			tprints(", ");
			printflags(rwf_flags, tcp->u_arg[flags_arg], "RWF_???");
		}
	}
	return 0;
}

SYS_FUNC(preadv)
{
	return do_preadv(tcp, -1);
}

static int
do_pwritev(struct tcb *tcp, const int flags_arg)
{
	kernel_ulong_t len =
		truncate_kulong_to_current_wordsize(tcp->u_arg[2]);

	printfd(tcp, tcp->u_arg[0]);
	tprints(", ");
	tprint_iov(tcp, len, tcp->u_arg[1], IOV_DECODE_STR);
	tprintf(", %" PRI_klu ", ", len);
	print_lld_from_low_high_val(tcp, 3);
	if (flags_arg >= 0) {
		tprints(", ");
		printflags(rwf_flags, tcp->u_arg[flags_arg], "RWF_???");
	}

	return RVAL_DECODED;
}

SYS_FUNC(pwritev)
{
	return do_pwritev(tcp, -1);
}

/*
 * x32 is the only architecture where preadv2 takes 5 arguments
 * instead of 6, see preadv64v2 in kernel sources.
 * Likewise, x32 is the only architecture where pwritev2 takes 5 arguments
 * instead of 6, see pwritev64v2 in kernel sources.
 */

#if defined X86_64
# define PREADV2_PWRITEV2_FLAGS_ARG_NO (current_personality == 2 ? 4 : 5)
#elif defined X32
# define PREADV2_PWRITEV2_FLAGS_ARG_NO (current_personality == 0 ? 4 : 5)
#else
# define PREADV2_PWRITEV2_FLAGS_ARG_NO 5
#endif

SYS_FUNC(preadv2)
{
	return do_preadv(tcp, PREADV2_PWRITEV2_FLAGS_ARG_NO);
}

SYS_FUNC(pwritev2)
{
	return do_pwritev(tcp, PREADV2_PWRITEV2_FLAGS_ARG_NO);
}

#include "xlat/splice_flags.h"

SYS_FUNC(tee)
{
	/* int fd_in */
	printfd(tcp, tcp->u_arg[0]);
	tprints(", ");
	/* int fd_out */
	printfd(tcp, tcp->u_arg[1]);
	tprints(", ");
	/* size_t len */
	tprintf("%" PRI_klu ", ", tcp->u_arg[2]);
	/* unsigned int flags */
	printflags(splice_flags, tcp->u_arg[3], "SPLICE_F_???");

	return RVAL_DECODED;
}

SYS_FUNC(splice)
{
	/* int fd_in */
	printfd(tcp, tcp->u_arg[0]);
	tprints(", ");
	/* loff_t *off_in */
	printnum_int64(tcp, tcp->u_arg[1], "%" PRId64);
	tprints(", ");
	/* int fd_out */
	printfd(tcp, tcp->u_arg[2]);
	tprints(", ");
	/* loff_t *off_out */
	printnum_int64(tcp, tcp->u_arg[3], "%" PRId64);
	tprints(", ");
	/* size_t len */
	tprintf("%" PRI_klu ", ", tcp->u_arg[4]);
	/* unsigned int flags */
	printflags(splice_flags, tcp->u_arg[5], "SPLICE_F_???");

	return RVAL_DECODED;
}

SYS_FUNC(vmsplice)
{
	/* int fd */
	printfd(tcp, tcp->u_arg[0]);
	tprints(", ");
	/* const struct iovec *iov, unsigned long nr_segs */
	tprint_iov(tcp, tcp->u_arg[2], tcp->u_arg[1], IOV_DECODE_STR);
	tprintf(", %" PRI_klu ", ", tcp->u_arg[2]);
	/* unsigned int flags */
	printflags(splice_flags, tcp->u_arg[3], "SPLICE_F_???");

	return RVAL_DECODED;
}
