#pragma once
#include <stdint.h>

struct qmux_platform_hdr {
	int total_msg_size;
	int qmux_client_id;
};

struct qmux_msg_hdr {
	int msg_type;
	int qmux_client_id;
	unsigned long qmux_txn_id;
	int sys_err_code;
	int qmi_err_code;
	int qmi_conn_id;
	int qmi_serv_id;
	uint8_t qmi_client_id;
	uint8_t ctrl_flags;
};

struct qmux_complete_hdr {
    struct qmux_platform_hdr platform;
    struct qmux_msg_hdr qmux;
};
