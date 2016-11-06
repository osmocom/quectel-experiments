#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <qmi.h>
#include <qmi_atcop_srvc.h>

static int g_qmi_handle = QMI_INVALID_CLIENT_HANDLE;
static int g_user_handle = -1;

static void at_command_cb(int user_handle, qmi_service_id_type service_id,
			  void *user_data, qmi_atcop_indication_id_type indication_id,
			  qmi_atcop_indication_data_type  *indication_data)
{
	printf("at_command_cb()\n");
}

static qmi_atcop_at_cmd_fwd_req_type at_cmd_fw_tbl[] = {
	{
		.num_of_cmds = 1,
		.qmi_atcop_at_cmd_fwd_req_type = {
			{ QMI_ATCOP_AT_CMD_NOT_ABORTABLE, "+SYSMO" },
		},
	},
};

static int register_atcmds(qmi_atcop_at_cmd_fwd_req_type *tbl, unsigned int num_cmds)
{
	unsigned int i;
	int rc, err_code;

	for (i = 0; i < num_cmds; i++) {
		printf("registering AT command '%s'\n", tbl[i].qmi_atcop_at_cmd_fwd_req_type[0].at_cmd_name);
		rc = qmi_atcop_reg_at_command_fwd_req(g_user_handle, &tbl[i], &err_code);
		if (rc < 0 || err_code != 0) {
			fprintf(stderr, "couldn't register command %s with QMI: Err %d\n",
				tbl[i].qmi_atcop_at_cmd_fwd_req_type[0].at_cmd_name, err_code);
			return -1;
		}
	}

	return 0;
}

static int init_atcop_by_port(const char *port)
{
	int i, err_code;
	int rc = -1;

	for (i = 1; i <= 5; i++) {
		rc = qmi_atcop_srvc_init_client(port, at_command_cb, NULL , &err_code);
		if (rc >= 0 && err_code == 0)
			break;
		else {
			printf("rc=%d, err_code=%d -> delaying %us...\n", rc, err_code, i);
			sleep(i);
			continue;
		}
	}

	return rc;
}

static int init(const char *qmi_port)
{
	int err_code;
	int rc;

	printf("sizeof(qmi_atcop_at_cmd_fwd_req_type): %d\n", sizeof(qmi_atcop_at_cmd_fwd_req_type));

	g_qmi_handle = qmi_init(NULL, NULL);
	if (g_qmi_handle == QMI_INVALID_CLIENT_HANDLE) {
		fprintf(stderr, "Error during qmi_init()\n");
		return -1;
	}

	rc = qmi_connection_init(qmi_port, &err_code);
	if (rc < 0) {
		fprintf(stderr, "Error during qmi_connection_init(): %d\n", err_code);
		return rc;
	}

	rc = init_atcop_by_port(qmi_port);
	if (rc < 0) {
		fprintf(stderr, "Error during init_atcop_by_portt(): %d\n", rc);
		return rc;
	}
	g_user_handle = rc;
	printf("g_user_handle=%d\n", g_user_handle);

	rc = register_atcmds(at_cmd_fw_tbl, sizeof(at_cmd_fw_tbl)/sizeof(at_cmd_fw_tbl[0]));
	if (rc < 0) {
		fprintf(stderr, "Error during register_atcmds(): %d\n", rc);
		return rc;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int rc;
	rc = init(argv[1]);
	if (rc < 0)
		exit(1);

	printf("Initialization done\n");

	exit(0);
}
