
SBOM_ROOTFS := $(BUILDDIR)/.sbom-rootfs
SBOM_STAMP  := $(SBOM_ROOTFS)/.extracted
SBOM_TRIVY  ?= trivy
SBOM_TRIVY_OPTS ?= --quiet --offline-scan

$(SBOM_STAMP): $(BASEIMAGE).tar
	@rm -rf $(SBOM_ROOTFS)
	@mkdir -p $(SBOM_ROOTFS)
	tar --exclude='dev/*' -xf $< -C $(SBOM_ROOTFS)
	@touch $@

ifeq ($(CONFIG_SBOM_CYCLONEDX),y)
IMAGES += $(BASEIMAGE).cdx.json
$(BASEIMAGE).cdx.json: $(SBOM_STAMP)
	$(SBOM_TRIVY) rootfs $(SBOM_TRIVY_OPTS) --format cyclonedx --output $@ $(SBOM_ROOTFS)
endif

ifeq ($(CONFIG_SBOM_SPDX),y)
IMAGES += $(BASEIMAGE).spdx
$(BASEIMAGE).spdx: $(SBOM_STAMP)
	$(SBOM_TRIVY) rootfs $(SBOM_TRIVY_OPTS) --format spdx --output $@ $(SBOM_ROOTFS)
endif

ifeq ($(CONFIG_SBOM_SPDX_JSON),y)
IMAGES += $(BASEIMAGE).spdx.json
$(BASEIMAGE).spdx.json: $(SBOM_STAMP)
	$(SBOM_TRIVY) rootfs $(SBOM_TRIVY_OPTS) --format spdx-json --output $@ $(SBOM_ROOTFS)
endif

ifeq ($(CONFIG_SBOM_GITHUB),y)
IMAGES += $(BASEIMAGE).github.json
$(BASEIMAGE).github.json: $(SBOM_STAMP)
	$(SBOM_TRIVY) rootfs $(SBOM_TRIVY_OPTS) --format github --output $@ $(SBOM_ROOTFS)
endif

ifeq ($(CONFIG_SBOM_TABLE),y)
IMAGES += $(BASEIMAGE).trivy.txt
$(BASEIMAGE).trivy.txt: $(SBOM_STAMP)
	$(SBOM_TRIVY) rootfs $(SBOM_TRIVY_OPTS) --format table --output $@ $(SBOM_ROOTFS)
endif

SBOM_FILES :=
ifeq ($(CONFIG_SBOM_CYCLONEDX),y)
SBOM_FILES += $(BASEIMAGE).cdx.json
endif
ifeq ($(CONFIG_SBOM_SPDX),y)
SBOM_FILES += $(BASEIMAGE).spdx
endif
ifeq ($(CONFIG_SBOM_SPDX_JSON),y)
SBOM_FILES += $(BASEIMAGE).spdx.json
endif
ifeq ($(CONFIG_SBOM_GITHUB),y)
SBOM_FILES += $(BASEIMAGE).github.json
endif
ifeq ($(CONFIG_SBOM_TABLE),y)
SBOM_FILES += $(BASEIMAGE).trivy.txt
endif

ifneq ($(SBOM_FILES),)

# Standalone SBOM zip: build/<image>.sbom.zip containing the sbom/ folder.
IMAGES += $(BASEIMAGE).sbom.zip
$(BASEIMAGE).sbom.zip: $(SBOM_FILES)
	@rm -rf $(BUILDDIR)/.sbom-stage
	@mkdir -p $(BUILDDIR)/.sbom-stage/sbom
	cp $(SBOM_FILES) $(BUILDDIR)/.sbom-stage/sbom/
	@rm -f $@
	cd $(BUILDDIR)/.sbom-stage && zip -r $(abspath $@) sbom
	@rm -rf $(BUILDDIR)/.sbom-stage

# Also append the sbom/ folder into the SWU-produced .zip when that format is selected.
ifeq ($(CONFIG_IMAGE_FORMAT_SWU),y)
IMAGES += $(BASEIMAGE).zip.sbom-stamp
$(BASEIMAGE).zip.sbom-stamp: $(BASEIMAGE).zip $(SBOM_FILES)
	@rm -rf $(BUILDDIR)/.sbom-stage
	@mkdir -p $(BUILDDIR)/.sbom-stage/sbom
	cp $(SBOM_FILES) $(BUILDDIR)/.sbom-stage/sbom/
	cd $(BUILDDIR)/.sbom-stage && zip -r $(abspath $(BASEIMAGE).zip) sbom
	@rm -rf $(BUILDDIR)/.sbom-stage
	@touch $@
endif

endif

sbom-clean:
	@rm -rf $(SBOM_ROOTFS) $(BUILDDIR)/.sbom-stage

.PHONY: sbom-clean
