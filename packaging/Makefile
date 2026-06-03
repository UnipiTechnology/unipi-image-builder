ifeq ($(CONFIG_IMAGE_FORMAT_VM), y)
include packaging/vm/Makefile
endif

ifeq ($(CONFIG_IMAGE_FORMAT_SWU), y)
include packaging/swu/Makefile
endif

ifeq ($(CONFIG_IMAGE_FORMAT_RAW),y)
include packaging/raw/Makefile
endif

ifeq ($(CONFIG_IMAGE_FORMAT_RAWMINI),y)
include packaging/mini/Makefile
endif

ifeq ($(CONFIG_IMAGE_FORMAT_RAWPART),y)
include packaging/part/Makefile
endif

ifeq ($(CONFIG_SBOM),y)
include packaging/sbom/Makefile
endif

