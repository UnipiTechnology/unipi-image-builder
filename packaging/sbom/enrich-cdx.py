#!/usr/bin/env python3
# Enrich the CycloneDX SBOM produced by 'trivy rootfs' with the fork
# lineage of the unipi-kernel component.
#
# Trivy emits the unipi-kernel component with its real deb identity
# (purl, supplier) but no CPE and no provenance. This step reads the
# structured upstream metadata that the unipi-kernel .deb installs at
# /usr/share/doc/unipi-kernel/upstream-metadata.json (see the kernel
# packaging repo: debian/scripts/gen-upstream-metadata) and injects:
#
#   - cpe              : cpe:2.3:o:linux:linux_kernel:<base_ver>:...
#                        so DependencyTrack's NVD analyzer matches the
#                        component against Linux kernel CVEs.
#   - pedigree         : ancestors (linux-cip -> linux), the applied
#                        hardware-enablement patchset, and the build
#                        commit — the authoritative fork lineage.
#   - externalReferences: the CIP kernel security advisory feed.
#
# The component keeps its honest identity (name, purl, supplier); we
# only add lineage. Nothing is invented — every value comes from the
# metadata file. If the metadata file is absent (older deb / non-kernel
# image) this script is a no-op so the build never fails.
#
# Usage: enrich-cdx.py <cdx.json> <sbom-rootfs>
#   reads  <sbom-rootfs>/usr/share/doc/unipi-kernel/upstream-metadata.json
#   rewrites <cdx.json> in place.

import json
import os
import sys

META_PATH = "usr/share/doc/unipi-kernel/upstream-metadata.json"


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: enrich-cdx.py <cdx.json> <sbom-rootfs>")

    cdx_path = sys.argv[1]
    rootfs = sys.argv[2]
    meta_path = os.path.join(rootfs, META_PATH)

    # No metadata -> nothing to enrich (no-op, not an error).
    if not os.path.exists(meta_path):
        return

    with open(meta_path) as f:
        meta = json.load(f)
    with open(cdx_path) as f:
        cdx = json.load(f)

    # Find the unipi-kernel component. Match by name; Trivy emits the
    # binary package name as the component name.
    components = cdx.get("components", [])
    comp = next((c for c in components if c.get("name") == "unipi-kernel"), None)
    if comp is None:
        # No unipi-kernel in this image (e.g. a non-kernel build). Skip.
        with open(cdx_path, "w") as f:
            json.dump(cdx, f, indent=2)
        return

    # CPE: match against NVD's linux_kernel product, using the base
    # Linux version (strip the CIP suffix) so NVD affected ranges apply.
    base_ver = ""
    for a in meta.get("ancestors", []):
        if a.get("name") == "linux":
            base_ver = a.get("version", "")
            break
    if base_ver:
        comp["cpe"] = f"cpe:2.3:o:linux:linux_kernel:{base_ver}:*:*:*:*:*:*:*"

    # Pedigree.ancestors: CycloneDX Component objects (need a `type`);
    # convert the metadata `repository` string into an externalReferences
    # entry, which is the CycloneDX-native shape.
    ancestors = []
    for a in meta.get("ancestors", []):
        anc = {"type": "library", "name": a["name"], "version": a["version"]}
        if a.get("purl"):
            anc["purl"] = a["purl"]
        if a.get("repository"):
            anc["externalReferences"] = [
                {"type": "vcs", "url": a["repository"]}
            ]
        ancestors.append(anc)

    pedigree = {"ancestors": ancestors}

    # Build commit -> pedigree.commits.
    commit = meta.get("build_commit", "")
    if commit:
        pedigree["commits"] = [{"uid": commit}]

    # Patchset -> pedigree.patches (type only; we deliberately do not
    # embed the private fork URL — patch names carry the intent).
    patches = meta.get("patches", [])
    if patches:
        pedigree["patches"] = [{"type": "unofficial"} for _ in patches]
        pedigree["notes"] = (
            "Fork of the CIP SLTS kernel with a minimal hardware-enablement "
            "patchset for UniPi boards. Patches (applied in order): "
            + ", ".join(patches)
            + ". Security advisories for this lineage are tracked by the CIP "
            "kernel security project, not by Debian's linux source package."
        )

    comp["pedigree"] = pedigree

    # Advisories feed as a component-level external reference.
    advisories = meta.get("advisories", "")
    if advisories:
        extrefs = comp.setdefault("externalReferences", [])
        if not any(e.get("url") == advisories for e in extrefs):
            extrefs.append({"type": "advisories", "url": advisories})

    with open(cdx_path, "w") as f:
        json.dump(cdx, f, indent=2)


if __name__ == "__main__":
    main()
