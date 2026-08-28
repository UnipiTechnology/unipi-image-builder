#!/usr/bin/env python3
# Adapt a kernel-generated CycloneDX VEX for upload to an image-level
# Dependency-Track project.
#
# The kernel repo generates a standalone VEX (debian/scripts/gen-vex)
# that points affects[].ref at the kernel's own purl. DependencyTrack's
# VEX importer does not resolve per-component bom-refs (DT #5260) — it
# only resolves the project's metadata.component bom-ref. This script
# rewrites all affects[].ref entries to the image SBOM's
# metadata.component bom-ref so DT actually applies the suppressions.
#
# Usage: gen-vex.py <image-sbom.cdx.json> <kernel-vex.cdx.json>
#   <image-sbom.cdx.json>  the (enriched) image CycloneDX SBOM
#   <kernel-vex.cdx.json>  the kernel's standalone VEX
#
# Output: adapted CycloneDX VEX JSON on stdout.
# If the image SBOM has no unipi-kernel component, an empty VEX is emitted.

import json
import os
import sys
from typing import Any


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit("usage: gen-vex.py <image-sbom.cdx.json> <kernel-vex.cdx.json>")
    sbom_path, vex_path = sys.argv[1:3]

    with open(sbom_path) as f:
        sbom: dict[str, Any] = json.load(f)

    # No kernel VEX shipped (e.g. the kernel .deb lacks cip-kernel-sec data):
    # emit an empty VEX so the image pipeline always produces a .vex.json.
    if not vex_path or not os.path.exists(vex_path):
        json.dump(_empty_vex(sbom), sys.stdout, indent=2)
        print()
        return

    with open(vex_path) as f:
        vex: dict[str, Any] = json.load(f)

    has_kernel = any(c.get("name") == "unipi-kernel"
                     for c in sbom.get("components", []))
    if not has_kernel:
        json.dump(_empty_vex(sbom), sys.stdout, indent=2)
        print()
        return

    project_ref = sbom.get("metadata", {}).get("component", {}).get("bom-ref", "")
    if not project_ref:
        sys.exit("gen-vex: image SBOM has no metadata.component bom-ref")

    # Rewrite all affects[].ref to the image project's bom-ref
    for vuln in vex.get("vulnerabilities", []):
        for affect in vuln.get("affects", []):
            affect["ref"] = project_ref

    # Update metadata to reflect the image project, not the kernel
    md = sbom.get("metadata", {})
    vex["metadata"]["component"] = {
        "type": md.get("component", {}).get("type", "application"),
        "bom-ref": project_ref,
        "name": md.get("component", {}).get("name", ""),
    }

    json.dump(vex, sys.stdout, indent=2)
    print()


def _empty_vex(sbom: dict[str, Any]) -> dict[str, Any]:
    md = sbom.get("metadata", {})
    comp = md.get("component", {})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "metadata": {
            "timestamp": md.get("timestamp", ""),
            "component": {
                "type": comp.get("type", "application"),
                "bom-ref": comp.get("bom-ref", ""),
                "name": comp.get("name", ""),
            },
        },
    }


if __name__ == "__main__":
    main()
