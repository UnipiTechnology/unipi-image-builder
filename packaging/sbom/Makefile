
# Top-level SBOM dispatcher. Pulls in the shared rootfs extraction, then
# the selected backend (Trivy or debsbom), and finally the zip bundler.

include packaging/sbom/Makefile.common

ifeq ($(CONFIG_SBOM_BACKEND_TRIVY),y)
include packaging/sbom/Makefile.trivy
endif

ifeq ($(CONFIG_SBOM_BACKEND_DEBSBOM),y)
include packaging/sbom/Makefile.debsbom
endif

include packaging/sbom/Makefile.bundle
