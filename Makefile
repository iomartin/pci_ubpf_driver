obj-m += pci-ubpf.o
ccflags-y := -std=gnu99

CFLAGS_MODULE += "-I/usr/local/include"

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) CFLAGS_MODULE=$(CFLAGS_MODULE) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) clean
