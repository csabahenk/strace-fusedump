#include <sys/fcntl.h>
#include <sys/stat.h>
#include "defs.h"
#include "syscall.h"

struct fdcontexttab fdcontexttab;

static int
pid_to_tgid(int pid)
{
	/* resurrected /proc/[pid]/status parsing code from d5c2daef */
	char buf[2048];
	char ppath[128];
	int sfd;
	int i;
	char *s;

	sprintf(ppath, "/proc/%d/status", pid);
	if ((sfd = open(ppath, O_RDONLY)) == -1) {
		perror(ppath);
		return -1;
	}

	i = read(sfd, buf, sizeof(buf));
	buf[i] = '\0';
	close(sfd);

	s = strstr(buf, "Tgid:\t");
	if (!s) {
		fprintf(stderr, "/proc/pid/status format error\n");
		return -1;
	}

	while (*s && *s++ != '\t')
		;
	return string_to_uint_ex(s, NULL, INT_MAX, "\n");
}

void
fdcontext_link(struct tcb *tcp)
{
	int index = -1;
	int i;
	int tgid;

	tgid = pid_to_tgid(tcp->pid);
	if (tgid == -1)
		error_msg_and_die("failed to find thread group id for pid %d", tcp->pid);
	tcp->tgid = tgid;

	for (i = 0; i < fdcontexttab.index_maxplus; i++) {
		if (fdcontexttab.entries[i].tgid == 0 ||
		    fdcontexttab.entries[i].tgid == tgid) {
			index = i;
			break;
		}
	}

	if (index == -1) {
		if (fdcontexttab.len == fdcontexttab.index_maxplus) {
			size_t newlen = fdcontexttab.len + 1;
			fdcontexttab.entries = xgrowarray(fdcontexttab.entries, &newlen,
							  sizeof(struct fdcontext));
			memset(fdcontexttab.entries + fdcontexttab.len, 0,
			       sizeof(struct fdcontext) * (newlen - fdcontexttab.len));
			fdcontexttab.len = newlen;
		}
		index = fdcontexttab.index_maxplus++;
	}

	tcp->fdcontext_index = index;
	fdcontexttab.entries[index].tgid = tgid;
	fdcontexttab.entries[index].refcount++;
}

void
fdcontext_drop(struct tcb *tcp)
{
	struct fdcontext *fdx;

	fdx = fdcontext(tcp);
	if (--fdx->refcount == 0) {
		free(fdx->entries);
		memset(fdx, 0, sizeof(*fdx));
	}
}

bool
fdcontext_get_entry(struct tcb *tcp, int fd, struct fdcontext_entry **fdxe)
{
	int oldlen;
	struct fdcontext *fdx;
	bool extant;

	fdx = fdcontext(tcp);

	oldlen = fdx->len;
#if 1
	if (fd >= fdx->len) {
		size_t newlen = fd + 1;

		fdx->entries = xgrowarray(fdx->entries, &newlen, sizeof(struct fdcontext_entry));
		fdx->len = newlen;
#else
	while (fd >= fdx->len)
		fdx->len = fdx->len * 2 + 1;
	if (fdx->len != oldlen) {
		fdx->entries = xreallocarray(fdx->entries, fdx->len,
					     sizeof(struct fdcontext_entry));
#endif
		memset(fdx->entries + oldlen, 0,
		       sizeof(struct fdcontext_entry) *
		       (fdx->len - oldlen));
	}

	if (fd >= fdx->fd_maxplus)
		fdx->fd_maxplus = fd + 1;

	*fdxe = fdx->entries + fd;

	extant = (*fdxe)->extant;
	(*fdxe)->extant = true;
	return extant;
}

void
fdcontext_del_entry(struct tcb *tcp, int fd)
{
	struct fdcontext *fdx;

	fdx = fdcontext(tcp);
	if (fd >= fdx->fd_maxplus) {
		debug_msg("%s: pid %d tgid %d sysc %s: fd=%d >= fd_maxplus=%d",
			  __func__, tcp->pid, tcp->tgid, tcp_sysent(tcp)->sys_name,
			  fd, fdx->fd_maxplus);
		return;
	}
	memset(fdx->entries + fd, 0, sizeof(struct fdcontext_entry));

	if (fd == fdx->fd_maxplus - 1) {
		while (fdx->fd_maxplus > 0 &&
		       !fdx->entries[fdx->fd_maxplus - 1].extant)
			fdx->fd_maxplus--;
	}
}

void
fdcontext_cleanup(struct tcb *tcp)
{
	char ppath[128];
	struct fdcontext *fdx;
	struct stat st;
	int fd;
	int ret;

	if (syserror(tcp))
		return;

	switch (tcp_sysent(tcp)->sen) {
	case SEN_close:
		fdcontext_del_entry(tcp, tcp->u_arg[0]);
		break;
	case SEN_execve:
	case SEN_execveat:
		fdx = fdcontext(tcp);

		for (fd = 0; fd < fdx->fd_maxplus; fd++) {
			snprintf(ppath, sizeof(ppath), "/proc/%d/fd/%d",
				 tcp->pid, fd);
			ret = stat(ppath, &st);
			if (ret == -1)
				fdcontext_del_entry(tcp, fd);
		}
		break;
	}
}
