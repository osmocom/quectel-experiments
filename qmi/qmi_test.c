#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <qmi_client.h>
#include <device_management_service_v01.h>
#include <network_access_service_v01.h>

static int g_qmi_handle = -1;

int main(int argc, char **argv)
{
	qmi_client_type clnt, notifier;
	qmi_cci_os_signal_type os_params;
	qmi_idl_service_object_type dm_service_obj;
	qmi_service_info info[10];
	uint32_t num_services, num_entries = 0;
	int rc;

	printf("== QMI Init...\n");
	g_qmi_handle = qmi_init(NULL, NULL);
	if (g_qmi_handle < 0) {
		fprintf(stderr, "qmi_init() failed: %d\n", g_qmi_handle);
		exit(1);
	}

	printf("== DMS Get Service Object...\n");
	dm_service_obj = dms_get_service_object_v01();
	if (!dm_service_obj) {
		fprintf(stderr, "Cannot get service object\n");
		return -1;
	}
	printf("== Client Notifier Init...\n");
	rc = qmi_client_notifier_init(dm_service_obj, &os_params, &notifier);

	/* wait for service and get number of services */
	while (1) {
		printf("Get Service List...\n");
		rc = qmi_client_get_service_list(dm_service_obj, NULL, NULL, &num_services);
		if (rc == QMI_NO_ERR)
			break;
		printf("Waiting for service to become available...\n");
		QMI_CCI_OS_SIGNAL_WAIT(&os_params, 0);
	}
	num_entries = num_services;
	printf("== %u services available\n", num_services);

	/* obtain service info */
	rc = qmi_client_get_service_list(dm_service_obj, info, &num_entries, &num_services);
	printf("== aqmi_client_get_service_list() returned %d num_entries = %d num_services = %d\n", rc, num_entries, num_services);

	rc = qmi_client_init(&info[0], dm_service_obj, NULL, NULL, NULL, &clnt);
	printf("== qmi_client_init() returned %d\n", rc);

	/* FIXME: main */
	dms_get_device_serial_numbers_resp_msg_v01 serno_resp;

	rc = qmi_client_send_msg_sync(clnt, QMI_DMS_GET_DEVICE_SERIAL_NUMBERS_REQ_V01, NULL, 0, &serno_resp, sizeof(serno_resp), 0);
	printf("== qmi_client_send_msg_sync() returned %d\n", rc);
	printf("== IMEI IS %s\n", serno_resp.imei_valid ? serno_resp.imei : "invalid");

	/* clean-up */
	printf("== qmi_client_release(clnt)\n");
	rc = qmi_client_release(clnt);
	printf("== qmi_client_release(notifier)\n");
	rc = qmi_client_release(notifier);
	sleep(1);
	exit(0);
}
