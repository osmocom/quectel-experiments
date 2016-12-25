#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

static char hexd_buff[4096];
static const char hex_chars[] = "0123456789abcdef";

static char *_osmo_hexdump(const unsigned char *buf, int len, char *delim)
{
	int i;
	char *cur = hexd_buff;

	hexd_buff[0] = 0;
	for (i = 0; i < len; i++) {
		const char *delimp = delim;
		int len_remain = sizeof(hexd_buff) - (cur - hexd_buff);
		if (len_remain < 3)
			break;

		*cur++ = hex_chars[buf[i] >> 4];
		*cur++ = hex_chars[buf[i] & 0xf];

		while (len_remain > 1 && *delimp) {
			*cur++ = *delimp++;
			len_remain--;
		}

		*cur = 0;
	}
	hexd_buff[sizeof(hexd_buff)-1] = 0;
	return hexd_buff;
}

static char *osmo_hexdump(const unsigned char *buf, int len)
{
	return _osmo_hexdump(buf, len, " ");
}




/* Function pointers to hold the value of the glibc functions */
static ssize_t (*real_write)(int fd, const void *buf, size_t count);
static ssize_t (*real_read)(int fd, void *buf, size_t count);
static int (*real_connect)(int fd, const struct sockaddr *addr, socklen_t addrlen);
static ssize_t (*real_send)(int sockfd, const void *buf, size_t len, int flags);
static ssize_t (*real_recv)(int sockfd, void *buf, size_t len, int flags);
static int (*real_close)(int fd);

static int trace_fds[16]= { -1, };
static int num_trace_fds = 0;

static void dump_qmuxd(int fd, int to_qmux, const void *buf, size_t len)
{
	int i;

	for (i = 0; i < num_trace_fds; i++) {
		if (trace_fds[i] == fd)
			printf("%s_qmuxd(%u, %04x): %s\n", to_qmux ? "to" : "from", fd, len, osmo_hexdump(buf, len));
	}
}

/* wrapping write function call */
ssize_t write(int fd, const void *buf, size_t count)
{
	dump_qmuxd(fd, 1, buf, count);

	if (!real_write)
		real_write = dlsym(RTLD_NEXT, "write");
	return real_write(fd, buf, count);
}

ssize_t read(int fd, void *buf, size_t count)
{
	dump_qmuxd(fd, 0, buf, count);

	if (!real_read)
		real_read = dlsym(RTLD_NEXT, "read");
	return real_read(fd, buf, count);
}

ssize_t send(int fd, const void *buf, size_t count, int flags)
{
	dump_qmuxd(fd, 1, buf, count);

	if (!real_send)
		real_send = dlsym(RTLD_NEXT, "send");
	return real_send(fd, buf, count, flags);
}

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
	dump_qmuxd(fd, 0, buf, len);

	if (!real_recv)
		real_recv = dlsym(RTLD_NEXT, "recv");
	return real_recv(fd, buf, len, flags);
}

int connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	if (addr->sa_family == AF_UNIX) {
		struct sockaddr_un *sun = (struct sockaddr_un *)addr;
		if (!strcmp(sun->sun_path, "/var/qmux_connect_socket")) {
			printf("Found socketfd to qmuxd: %d\n", fd);
			trace_fds[num_trace_fds++] = fd;
		}
	}

	if (!real_connect)
		real_connect = dlsym(RTLD_NEXT, "connect");
	return real_connect(fd, addr, addrlen);
}

int close(int fd)
{
	int i;

	for (i = 0; i < num_trace_fds; i++) {
		if (trace_fds[i] == fd) {
			printf("Closed socketfd to qmuxd: %d\n", fd);
			trace_fds[i] = -1;
		}
	}
	if (!real_close)
		real_close = dlsym(RTLD_NEXT, "close");
	return real_close(fd);
}
