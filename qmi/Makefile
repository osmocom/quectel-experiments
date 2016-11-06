ANDRO_VEND_QCOM_INC ?= $(HOME)/projects/git/android_vendor_qcom_proprietary
QMI_LIBDIR ?= $(HOME)/projects/kommerz/sysmocom/quectel/EC20/files/usr/lib
CROSS_COMPILE ?= arm-oe-linux-gnueabi-

QMI_CFLAGS := -I$(ANDRO_VEND_QCOM_INC)/qmi/inc -I$(ANDRO_VEND_QCOM_INC)/qmi/services -I$(ANDRO_VEND_QCOM_INC)/qmi/platform -I$(ANDRO_VEND_QCOM_INC)/qmi-framework/inc
QMI_LIBS := -L$(QMI_LIBDIR) -lqmi -lqmiservices -lqmi_cci

CFLAGS := $(QMI_CFLAGS) -Wno-unused-function -Wall 
LDFLAGS := $(QMI_LIBS)

CFLAGS += $(EXTRA_CFLAGS)

all: qmi_test atcop_test

qmi_test: qmi_test.o
	$(CC) $(LDFLAGS) -o $@ $^

atcop_test: atcop_test.o
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm -f *.o qmi_test atcop_test

push: qmi_test atcop_test
	adb push qmi_test /cache/tmp/
	adb push atcop_test /cache/tmp/
