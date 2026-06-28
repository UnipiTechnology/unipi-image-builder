
BUILDDIR := build
export BUILDDIR
ADDONS := addons

.DEFAULT_GOAL = all

BUILDTMPDIR=tmp
export BUILDTMPDIR

mmopt-y = --hook-dir=/usr/share/mmdebstrap/hooks/maybe-merged-usr
#mmpre-y = --hook-dir=/usr/share/mmdebstrap/hooks/file-mirror-automount
mmpre-y += --customize-hook='mv -f "$$1/etc/resolv.conf" "$$1/etc/.resolv.conf"'
mmpre-y += --customize-hook='upload resolv.conf /etc/resolv.conf'
mmpost-y = --customize-hook='mv -f "$$1/etc/.resolv.conf" "$$1/etc/resolv.conf"'
skip-n =
components-y=

Makefile.addons Kconfig.addons &: $(ADDONS)
	@( for i in $(wildcard $(ADDONS)/*/Makefile); do echo "include $$i"; done ) > Makefile.addons
	@( for i in $(wildcard $(ADDONS)/*/Kconfig); do echo "source \"$$i\""; done ) > Kconfig.addons


include Makefile.inc
include Makefile.addons

IMAGE_NAME := $(subst ",,$(CONFIG_DEBIAN_SUITE))-$(subst ",,$(CONFIG_PRODUCT))
BASEIMAGE := $(BUILDDIR)/$(IMAGE_NAME)$(if $(IMAGE_VERSION),_$(IMAGE_VERSION),)
IMAGES := $(BASEIMAGE).tar

ifeq ($(CONFIG_UNIPI_32_BIT),y)
  ARCH = armhf
else
ifeq ($(CONFIG_UNIPI_SOURCE),y)
  ARCH = arm64
else
  ARCH = $(CONFIG_ARCHITECTURE)
endif
endif
ARCHITECTURE := $(patsubst %,--architecture %, $(ARCH) $(CONFIG_FOREIGN_ARCHITECTURE))

export DEBIAN_SUITE=$(subst ",,$(CONFIG_DEBIAN_SUITE))

-include packaging/Makefile
-include volumes/Makefile

%_defconfig:
	@if ! [ -f Kconfig.format.add ]; then touch Kconfig.format.add; fi
	kconfig-conf --defconfig=configs/$@ Kconfig
	KCONFIG_CONFIG=.format kconfig-conf --defconfig=configs/$@ Kconfig.format

local-upload = $(shell build-tools/setup-local-upload $(local-pkgs-y))
local-pkgs += $(patsubst %,--include=/tmp/%, $(notdir $(local-pkgs-y)))

$(BASEIMAGE).tar: Makefile.inc .config #Makefile
	@mkdir -p "$(BUILDDIR)"
	@bash -c '$(patsubst %,cp % /tmp;, $(local-pkgs-y))'
	@bash -c '$(patsubst %,build-tools/source-prepare.sh %;, $(sources-y))'
	@bash -c 'set -eu; $(patsubst %,%;, $(check-y))'
	HOME=/tmp /usr/bin/mmdebstrap\
	    --variant=$(BUILD_VARIANT)\
	    --format=tar\
	    $(ARCHITECTURE)\
	    $(patsubst %,--components=%, $(components-y))\
	    $(patsubst %,--include=%, $(pkgs-y))\
	    $(patsubst %,--setup-hook=$(BUILDTMPDIR)/.%, $(notdir $(sources-y)))\
	    $(local-upload)\
	    $(local-pkgs)\
	    $(mmpre-y)\
	    $(mmopt-y)\
	    $(mmpost-y)\
	    --customize-hook=build-tools/source-post.sh\
	    $(skip-n) \
	    $(CONFIG_DEBIAN_SUITE) $(BASEIMAGE).tmp\
	    $(if $(V),--verbose,)
	@mv $(BASEIMAGE).tmp $(BASEIMAGE).tar


all: $(IMAGES)

next:
	@bash -c '$(patsubst %,build-tools/source-prepare.sh %;, $(sources-y))'
	HOME=/tmp /usr/bin/mmdebstrap\
	    --skip=check/empty,$(SKIP)\
	    --variant=custom\
	    --format=tar\
	    $(ARCHITECTURE)\
	    --setup-hook='mmtarfilter "--path-exclude=/dev/*" < $(BASEIMAGE).tar | tar -C "$$1" -x'\
	    $(ADDON)\
	    --customize-hook=build-tools/source-post.sh\
	    $(CONFIG_DEBIAN_SUITE) $(BASEIMAGE)-1.tar\
	    $(if $(V),--verbose,)

#	    --setup-hook=build-tools/source-pre.sh\
#	    $(patsubst %,--setup-hook=$(BUILDDIR)/.%, $(notdir $(sources-y)))\

menuconfig: Kconfig.addons
	@kconfig-mconf Kconfig
	@build-tools/hash_passwd.sh .config

format:
	@if ! [ -f Kconfig.format.add ]; then touch Kconfig.format.add; fi
	@KCONFIG_CONFIG=.format kconfig-mconf Kconfig.format


savedefconfig: .config
	@kconfig-conf --savedefconfig defconfig Kconfig
	@KCONFIG_CONFIG=.format kconfig-conf --savedefconfig defconfig.format Kconfig.format
	@cat defconfig.format >> defconfig
	@rm defconfig.format

