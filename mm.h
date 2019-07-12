#ifndef mm_mm_h
#define mm_mm_h

struct seccomp_user_notif {
	int fd;
	struct seccomp_notif *notif;
	struct seccomp_notif_resp *resp;
};

int seccomp_install_filter(void);
struct seccomp_user_notif *seccomp_user_notif_recv(int fd);
int seccomp_user_notif_send(int fd, struct seccomp_user_notif *user);
int seccomp_user_notif_valid(struct seccomp_user_notif *user);

#endif
