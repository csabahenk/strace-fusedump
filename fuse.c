#include "defs.h"
#include <sys/stat.h>
#include <sys/uio.h>
#include "syscall.h"

int fuse_dumpfd = -1;
static char *fuse_dumpbuf = NULL;
static size_t fuse_dumpbufsize = 8192;

enum fuse_fd_status {
	FD_FUSE_UNSET,
	FD_FUSE_YES,
	FD_FUSE_NO
};


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

static bool
fuse_check(struct tcb *tcp, int fd, enum existence_spec extant)
{
	struct stat st;
	char ppath[128];
	int rv;
	struct fdcontext_entry *fdxe;
	struct fuse_fdcontext_entry *ffdxe;

	fdcontext_get_entry(tcp, fd, &fdxe);
	ffdxe = &fdxe->fuse_fdcontext_entry;

	if (extant == (ffdxe->fd_status == FD_FUSE_UNSET ? IT_IS : IT_ISNT))
		error_msg_and_die("%s: in syscall %s fdcontext_entry "
			"of fd %d: fuse fd existence spec: %d, status: %d",
			__func__,  tcp_sysent(tcp)->sys_name, fd, extant,
			ffdxe->fd_status);
	if (ffdxe->fd_status == FD_FUSE_UNSET) {
		snprintf(ppath, sizeof(ppath), "/proc/%d/fd/%d", tcp->pid, fd);
		rv = stat(ppath, &st);

		ffdxe->fd_status = (rv == 0 &&
				    st.st_rdev == 0xae5 /* makedev(10, 229) */ ) ?
				   FD_FUSE_YES : FD_FUSE_NO;
	}
	return ffdxe->fd_status == FD_FUSE_YES;
}

struct fusedump_timespec {
	uint32_t len;
	uint64_t sec;
	uint32_t nsec;
} __attribute__((packed));

struct fusedump_signature {
	uint32_t len;
	char sig[5];
} __attribute__((packed));

static void
fusedump_gettime (struct fusedump_timespec *fts)
{
	struct timespec ts = {0,};

	clock_gettime (CLOCK_REALTIME, &ts);

	fts->sec  = ts.tv_sec;
	fts->nsec = ts.tv_nsec;
}

static void
fuse_printmark(struct tcb *tcp, char mark)
{
	char signature[] = {'S', 'T', 'R', 'A', 0xCE};
	struct iovec iovs[4];
	uint32_t fusedump_item_count = 3;
	struct fusedump_timespec fts;
	struct fusedump_signature fsig;

	fts.len = sizeof (fts);
	fusedump_gettime (&fts);
	fsig.len = sizeof (fsig);
	memcpy (fsig.sig, signature, sizeof(signature));

	iovs[0] = (struct iovec){ &mark, sizeof (mark) };
	iovs[1] = (struct iovec){ &fusedump_item_count,
				  sizeof (fusedump_item_count) };
	iovs[2] = (struct iovec){ &fts, fts.len };
	iovs[3] = (struct iovec){ &fsig, fsig.len };

	if (writev(fuse_dumpfd, iovs, 4) == -1)
		error_msg_and_die("cannot write to fuse dumpfile: %s",
				  strerror(errno));
}

static void
fuse_dumpio(struct tcb *tcp, kernel_ulong_t addr, size_t size)
{
	fuse_initdumpbuf(size);

	if (umoven(tcp, addr, size, fuse_dumpbuf))
		error_msg_and_die("cannot read data from %#" PRIx64,
				  addr);
	if (write(fuse_dumpfd, fuse_dumpbuf, size) != (ssize_t)size)
		error_msg_and_die("cannot write to fuse dumpfile: %s",
				  strerror(errno));
}

void
dumpio_fuse(struct tcb *tcp)
{
	int fd;
	enum existence_spec extant;

	if (syserror(tcp) || fuse_dumpfd == -1)
		return;

	switch (tcp_sysent(tcp)->sen) {
	case SEN_open:
	case SEN_openat:
		fd = tcp->u_rval;
		extant = IT_ISNT;
		break;
	case SEN_read:
	case SEN_write:
	case SEN_readv:
	case SEN_writev:
		fd = tcp->u_arg[0];
		extant = IT_UNCERTAIN;
		break;
	default:
		return;
	}
	if (!fuse_check(tcp, fd, extant))
		return;

	switch (tcp_sysent(tcp)->sen) {
	case SEN_read:
		fuse_printmark(tcp, 'R');
		fuse_dumpio(tcp, tcp->u_arg[1], tcp->u_rval);
		break;
	case SEN_write:
		fuse_printmark(tcp, 'W');
		fuse_dumpio(tcp, tcp->u_arg[1], tcp->u_arg[2]);
		break;
	case SEN_readv:
		fuse_printmark(tcp, 'R');
		dumpiov_upto_cbk(tcp, tcp->u_arg[2], tcp->u_arg[1],
			         tcp->u_rval, false,  fuse_dumpio);
		break;
	case SEN_writev:
		fuse_printmark(tcp, 'W');
		dumpiov_upto_cbk(tcp, tcp->u_arg[2], tcp->u_arg[1],
			         -1, false, fuse_dumpio);
		break;
	}
}
