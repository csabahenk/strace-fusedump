#include "defs.h"
#include <dirent.h>
#include "largefile_wrappers.h"
#include "syscall.h"

static void
iogroup_merge(struct tcb *tcp, int fd1, int fd2, enum existence_spec extant)
{
	struct fdcontext *fdx;
	struct fdcontext_entry *fdxe;
	struct iogroup_fdcontext_entry *ifdxes[2];
	int i, fds[2] = {fd1, fd2};
	enum existence_spec xspecs[2] = {IT_IS, extant};
	unsigned *g;

	for (i=0; i < 2; i++) {
		fdcontext_get_entry(tcp, fds[i], &fdxe);
		ifdxes[i] = &fdxe->iogroup_fdcontext_entry;
		if (xspecs[i] == (ifdxes[i]->group ? IT_ISNT : IT_IS))
			error_msg_and_die("%s: in syscall %s: fd %d [idx %d]: "
					"existence spec: %d, io group: %d",
					__func__, tcp_sysent(tcp)->sys_name,
					fds[i], i, xspecs[i], ifdxes[i]->group);
	}

	if (!ifdxes[1]->group) {
		ifdxes[1]->group = ifdxes[0]->group;
		return;
	}

	fdx = fdcontext(tcp);
	for (i = 0; i < fdx->fd_maxplus; i++) {
		g = &fdx->entries[i].iogroup_fdcontext_entry.group;
		if (*g == ifdxes[1]->group)
			*g = ifdxes[0]->group;
	}
}

void
fdcontext_iogroup_init(struct tcb *tcp, bool enabled)
{
	char ppath[128];
	DIR *dir;
	struct_dirent *de;
	struct fdcontext *fdx;
	struct fdcontext_entry *fdxe;
	struct iogroup_fdcontext_entry *ifdxe;

	fdx = fdcontext(tcp);
	fdx->iogroup_fdcontext.enabled = enabled;
	if (!enabled)
		return;

	snprintf(ppath, sizeof(ppath), "/proc/%d/fd",
		 tcp->pid);

	dir = opendir(ppath);
	if (!dir) {
		debug_msg("failed to open %s", ppath);
		return;
	}

	while ((de = read_dir(dir)) != NULL) {
		int fd;
		/*
		if (de->d_fileno == 0)
			continue;
		 */

		if (strcmp(de->d_name, ".") == 0 ||
		    strcmp(de->d_name, "..") == 0)
			continue;

		fd = string_to_uint(de->d_name);
		if (fd == -1) {
			debug_msg("weird entry in %s: %s", ppath, de->d_name);
			continue;
		}

		fdcontext_get_entry(tcp, fd, &fdxe);
		ifdxe = &fdxe->iogroup_fdcontext_entry;
		if (!ifdxe->group)
			ifdxe->group = ++fdx->iogroup_fdcontext.group_max;

	}

	closedir(dir);
}

void
fdcontext_iogroup_hook(struct tcb *tcp, bool is_rval_fd)
{
	struct fdcontext *fdx;
	struct fdcontext_entry *fdxe;
	struct iogroup_fdcontext_entry *ifdxe;
	int i = -1;
	int j = -1;

	fdx = fdcontext(tcp);
	if (syserror(tcp) || !fdx->iogroup_fdcontext.enabled)
		return;

	if (is_rval_fd) {
		switch (tcp_sysent(tcp)->sen) {
		/* dup-like syscalls */
		case SEN_dup:
		case SEN_dup2:
		case SEN_dup3:
		/* this is then fcntl(F_DUPFD) */
		case SEN_fcntl:
		case SEN_fcntl64:
			iogroup_merge(tcp, tcp->u_arg[0], tcp->u_rval,
				      IT_UNCERTAIN);
			break;
		default:
		/* open-like syscalls */
			fdcontext_get_entry(tcp, tcp->u_rval, &fdxe);
			ifdxe = &fdxe->iogroup_fdcontext_entry;

			if (ifdxe->group)
				error_msg_and_die("%s: in syscall %s fdcontext_entry "
					"of fd %ld is extant in open-like function",
					__func__,
					tcp_sysent(tcp)->sys_name,
					tcp->u_rval);
			ifdxe->group = ++fdx->iogroup_fdcontext.group_max;
		}

		return;
	}

	switch (tcp_sysent(tcp)->sen) {
	case SEN_sendfile64:
	case SEN_tee:
		i = 0;
		j = 1;
		break;
	case SEN_copy_file_range:
	case SEN_splice:
		i = 0;
		j = 2;
		break;
	case SEN_pipe:
	case SEN_pipe2:
		i = 0;
		break;
	case SEN_socketpair:
		i = 3;
		break;
	}

	if (i == -1)
		return;

	if (j == -1) {
		/* pipe-like syscalls */
		int pair[2];

		if (umove(tcp, tcp->u_arg[i], &pair) == -1)
			debug_msg("%s: in syscall %s umove(... tcp->u_arg[%d] faied",
				  __func__, tcp_sysent(tcp)->sys_name, i);
		else {
			int group = 0;
			int k;

			for (k = 0; k < 2; k++) {
				fdcontext_get_entry(tcp, pair[k], &fdxe);
				ifdxe = &fdxe->iogroup_fdcontext_entry;

				if (ifdxe->group)
					error_msg_and_die("%s: in syscall %s fdcontext_entry "
						"of fd %d is extant in pipe-like function",
						__func__,
						tcp_sysent(tcp)->sys_name,
						pair[k]);
				if (!group)
					group = ++fdx->iogroup_fdcontext.group_max;
				ifdxe->group = group;
			}
		}
	} else
		/* splice-like syscalls */
		iogroup_merge(tcp, tcp->u_arg[i], tcp->u_arg[j], IT_IS);
}
