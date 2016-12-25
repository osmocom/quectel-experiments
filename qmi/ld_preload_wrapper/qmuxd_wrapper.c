#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "qmuxd_protocol.h"

static __thread char hexd_buff[4096];
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

enum stream_state {
	ST_ACTIVE,
	ST_WAIT_CLID,
	ST_WAIT_SYNC,
};

enum msg_state {
	MSG_ST_WAIT_PH,
	MSG_ST_WAIT_QH,
	MSG_ST_PAYLOAD,
};

struct qmuxd_fd;

struct qmuxd_stream {
	struct qmuxd_fd *qfd;
	enum stream_state stream_state;
	enum msg_state msg_state;
	uint8_t buf[0xffff];
	unsigned int buf_used;
	int cur_msg_len;
	int qmux_client_id;
	struct qmux_complete_hdr *qch;
	int to_qmuxd;
};

struct qmuxd_fd {
	int fd;
	struct qmuxd_stream to_qmuxd;
	struct qmuxd_stream from_qmuxd;
};

#define STR_PR(qs, fmt, args ...)	\
	printf("%d %s " fmt, (qs)->qfd->fd, (qs)->to_qmuxd ? "=>" : "<=", ## args)

#ifdef DEBUG
#define STR_PR_DBG(qs, fmt, args ...)	STR_PR(qs, fmt, ## args)
#else
#define STR_PR_DBG(qs, fmt, args ...)
#endif

static struct qmuxd_fd trace_fds[16] = { { .fd = -1, }, };
static int num_trace_fds = 0;

static void init_trace_stream(struct qmuxd_stream *qs, int to_qmuxd, struct qmuxd_fd *qfd)
{
	memset(qs, 0, sizeof(*qs));
	qs->qfd = qfd;
	qs->to_qmuxd = to_qmuxd;
	qs->qch = (struct qmux_complete_hdr *) qs->buf;
	qs->msg_state = MSG_ST_WAIT_PH;
	if (qs->to_qmuxd) {
		qs->stream_state = ST_ACTIVE;
	} else {
		qs->stream_state = ST_WAIT_CLID;
	}
}

static void init_trace_fd(struct qmuxd_fd *qfd, int fd)
{
	memset(qfd, 0, sizeof(*qfd));
	qfd->fd = fd;
	init_trace_stream(&qfd->to_qmuxd, 1, qfd);
	init_trace_stream(&qfd->from_qmuxd, 0, qfd);
}

static void stream_append(struct qmuxd_stream *qs, const void *data, size_t len)
{
	int buf_remain = sizeof(qs->buf) - qs->buf_used;

	if (buf_remain < len) {
		STR_PR(qs, "strem buffer oveflow\n");
		exit(2342);
	}

	memcpy(qs->buf + qs->buf_used, data, len);
	qs->buf_used += len;
}

static void stream_consume(struct qmuxd_stream *qs, size_t len)
{
	STR_PR_DBG(qs, "consuming %u bytes from head of stream\n", len);
	if (len >= qs->buf_used) {
		memset(qs->buf, 0, sizeof(qs->buf));
		qs->buf_used = 0;
	} else {
		memmove(qs->buf, qs->buf+len, qs->buf_used-len);
		qs->buf_used -= len;
	}
}

static void _handle_data(struct qmuxd_fd *qfd, int to_qmux, const void *data, size_t len)
{
	struct qmuxd_stream *qs;
	struct qmux_complete_hdr *qch;

	if (to_qmux)
		qs = &qfd->to_qmuxd;
	else
		qs = &qfd->from_qmuxd;

	STR_PR_DBG(qs, "raw(%04x): %s\n", len, osmo_hexdump(data, len));

	stream_append(qs, data, len);

	switch (qs->stream_state) {
	case ST_WAIT_CLID:
		if (qs->buf_used >= 4) {
			stream_consume(qs, 4);
			STR_PR_DBG(qs, "transitioning ST_WAIT_CLID->ST_ACTIVE\n");
			qs->stream_state = ST_ACTIVE;
		}
		break;
	case ST_WAIT_SYNC:
		/* FIXME */
		break;
	case ST_ACTIVE:
		switch (qs->msg_state) {
		case MSG_ST_WAIT_PH:
			if (qs->buf_used >= sizeof(qs->qch->platform)) {
				qs->cur_msg_len = qs->qch->platform.total_msg_size;
				if (qs->cur_msg_len == 0)
					qs->cur_msg_len = 0x2c0;
				qs->qmux_client_id = qs->qch->platform.qmux_client_id;
				STR_PR_DBG(qs, "msg_len=0x%x, cli_id=0x%x -> MSG_ST_WAIT_QH\n", qs->cur_msg_len, qs->qmux_client_id);
				qs->msg_state = MSG_ST_WAIT_QH;
			}
			/* fall-through */
		case MSG_ST_WAIT_QH:
			if (qs->buf_used >= sizeof(*qs->qch)) {
				qs->msg_state = MSG_ST_PAYLOAD;
				STR_PR_DBG(qs, "->MSG_ST_PAYLOAD\n");
			}
			/* fall-through */
		case MSG_ST_PAYLOAD:
			if (qs->buf_used >= qs->cur_msg_len) {
				qch = qs->qch;
				STR_PR(qs, "COMPL(CLI=0x%02x, MSGT=0x%02x, TXN=0x%lx, sERR=%u, qERR=%u, qConn=%u, qServ=0x%02x, qmiCLI=0x%x, flags=0x%x): %s\n",
					qch->platform.qmux_client_id, qch->qmux.msg_type, qch->qmux.qmux_txn_id, qch->qmux.sys_err_code, qch->qmux.qmi_err_code,
					qch->qmux.qmi_conn_id, qch->qmux.qmi_serv_id, qch->qmux.qmi_client_id, qch->qmux.ctrl_flags,
					osmo_hexdump(qs->buf+sizeof(*qch), qs->buf_used - sizeof(*qch)));
				stream_consume(qs, qs->cur_msg_len);
				qs->msg_state = MSG_ST_WAIT_PH;
			}
			break;
		}
		break;
	}
}

static void handle_data(int fd, int to_qmux, const void *data, size_t len)
{
	int i;

	for (i = 0; i < num_trace_fds; i++) {
		struct qmuxd_fd *qfd = &trace_fds[i];
		if (qfd->fd == fd) {
			_handle_data(qfd, to_qmux, data, len);
			break;
		}
	}
}




/* Function pointers to hold the value of the glibc functions */
static ssize_t (*real_write)(int fd, const void *buf, size_t count);
static ssize_t (*real_read)(int fd, void *buf, size_t count);
static int (*real_connect)(int fd, const struct sockaddr *addr, socklen_t addrlen);
static ssize_t (*real_send)(int sockfd, const void *buf, size_t len, int flags);
static ssize_t (*real_recv)(int sockfd, void *buf, size_t len, int flags);
static int (*real_close)(int fd);


/* wrapping write function call */
ssize_t write(int fd, const void *buf, size_t count)
{
	handle_data(fd, 1, buf, count);

	if (!real_write)
		real_write = dlsym(RTLD_NEXT, "write");
	return real_write(fd, buf, count);
}

ssize_t read(int fd, void *buf, size_t count)
{
	ssize_t rc;

	if (!real_read)
		real_read = dlsym(RTLD_NEXT, "read");

	rc = real_read(fd, buf, count);
	handle_data(fd, 0, buf, count);

	return rc;
}

ssize_t send(int fd, const void *buf, size_t count, int flags)
{
	handle_data(fd, 1, buf, count);

	if (!real_send)
		real_send = dlsym(RTLD_NEXT, "send");
	return real_send(fd, buf, count, flags);
}

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
	ssize_t rc;

	if (!real_recv)
		real_recv = dlsym(RTLD_NEXT, "recv");

	rc = real_recv(fd, buf, len, flags);
	handle_data(fd, 0, buf, len);

	return rc;
}

int connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
	if (addr->sa_family == AF_UNIX) {
		struct sockaddr_un *sun = (struct sockaddr_un *)addr;
		if (!strcmp(sun->sun_path, "/var/qmux_connect_socket")) {
			printf("Found socketfd to qmuxd: %d\n", fd);
			init_trace_fd(&trace_fds[num_trace_fds++], fd);
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
		if (trace_fds[i].fd == fd) {
			printf("Closed socketfd to qmuxd: %d\n", fd);
			trace_fds[i].fd = -1;
		}
	}
	if (!real_close)
		real_close = dlsym(RTLD_NEXT, "close");
	return real_close(fd);
}
