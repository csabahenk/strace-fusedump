#include "defs.h"
#include <sys/stat.h>
#include <sys/uio.h>

int fuse_dumpfd = -1;
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

bool
fuse_check(struct tcb *tcp)
{
	struct stat st;
	char ppath[128];
	int rv;

	if (fuse_dumpfd == -1)
		return 0;

	snprintf(ppath, sizeof(ppath), "/proc/%d/fd/%ld", tcp->pid,
		 tcp->u_arg[0]);
	rv = stat(ppath, &st);
	return (rv == 0 && st.st_rdev == 0xae5 /* makedev(10, 229) */ );
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

void
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

void
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
