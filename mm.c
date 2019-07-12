#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "mm.h"

static int size_seccomp_notif = -1;
static int size_seccomp_notif_resp = -1;

static int seccomp(unsigned int operation, unsigned int flags, void *args)
{
	return syscall((long) SYS_seccomp, (long) operation, (long) flags, (long) args);
}

static int seccomp_get_sizes(void)
{
	struct seccomp_notif_sizes sizes;
	int ret;
	if ((size_seccomp_notif != -1) && (size_seccomp_notif_resp != -1)) {
		return 0;
	}
	memset(&sizes, 0, sizeof(sizes));
	if ((ret = seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes)) == 0) {
		size_seccomp_notif = sizes.seccomp_notif;
		size_seccomp_notif_resp = sizes.seccomp_notif_resp;
	}
	return ret;
}

int seccomp_install_filter(void)
{
	int ret;
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, arch)), /* load arch field */
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 1, 0),            /* if arch is x86_64, skip next instruction */
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),                          /* handle the syscall normally */
		BPF_STMT(BPF_LD|BPF_ABS, offsetof(struct seccomp_data, nr)),         /* load the syscall number */
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_getuid, 2, 0),                   /* if it's getuid(), skip 2 instructions */
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_getgid, 1, 0),                   /* if it's getgid(), skip 1 instruction */
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),                          /* handle the syscall normally */
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_USER_NOTIF),                     /* let the userspace listener handle it */
	};
	struct sock_fprog prog = {
		.len = sizeof(filter)/sizeof(filter[0]),
		.filter = filter,
	};
	ret = seccomp_get_sizes();
	if (ret != 0) {
		return ret;
	}
	if ((ret = prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL)) != 0) { /* todo: only need this step if we don't have CAP_SYS_ADMIN */
		return ret;
	}
	return seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog); /* returns new listener FD, or -1 */
}

/* wait for a notification from the kernel, allocate the response buffer, and return them both */
struct seccomp_user_notif *seccomp_user_notif_recv(int fd)
{
	struct seccomp_user_notif *user;
	user = calloc(1, sizeof(struct seccomp_user_notif));
	if (user == NULL) {
		return NULL;
	}
	user->fd = fd;
	user->notif = calloc(1, size_seccomp_notif);
	if (user->notif == NULL) {
		free(user);
		return NULL;
	}
	user->resp = calloc(1, size_seccomp_notif_resp);
	if (user->resp == NULL) {
		free(user->notif);
		free(user);
		return NULL;
	}
	if (ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, user->notif) != 0) {
		return NULL;
	}
	user->resp->id = user->notif->id;
	return user;
}

/* check if the PID that issued the syscall is still the same process */
int seccomp_user_notif_valid(struct seccomp_user_notif *user)
{
	return ioctl(user->fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &user->notif->id);
}

/* reply to the kernel, and free up resources */
int seccomp_user_notif_send(int fd, struct seccomp_user_notif *user)
{
	int ret;
	ret = ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, user->resp);
	free(user->resp);
	free(user->notif);
	free(user);
	return ret;
}
