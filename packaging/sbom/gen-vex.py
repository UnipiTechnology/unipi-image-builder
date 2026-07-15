#!/usr/bin/env python3
# Generate a CycloneDX VEX (Vulnerability Exploitability eXchange) for the
# unipi-kernel component, from the output of cip-kernel-sec's
# report_affected.py (https://gitlab.com/cip-project/cip-kernel/cip-kernel-sec).
#
# Purpose: the SBOM's unipi-kernel component carries a
# cpe:2.3:o:linux:linux_kernel:<ver> so DependencyTrack's NVD analyzer
# matches it against Linux kernel CVEs. NVD does not know which CVEs the
# CIP SLTS branch has already backported or ignored. This VEX marks those
# CVEs as resolved / not_affected so DT suppresses them, leaving only
# genuinely open kernel CVEs visible.
#
# Input: the YAML output of
#   report_affected.py --output-format yaml -o <file> --branch cip/12:<tag>
# which classifies every tracked kernel CVE for the branch into three
# buckets:
#     affected -> open      (NOT VEXed; DT surfaces via CPE)
#     fixed    -> resolved  (VEXed: resolved, will_not_fix)
#     ignored  -> not_affected (VEXed: not_affected)
# Pass the branch with the exact built tag, e.g. `cip/6.12:v6.12.94-cip26`,
# so the classification matches the kernel actually shipped (not the branch
# tip).
#
# Usage: gen-vex.py <cdx.json> <sbom-rootfs> <report.yaml>
#   <cdx.json>     the (enriched) CycloneDX SBOM, for the component ref + timestamp
#   <sbom-rootfs>  extracted rootfs (reserved; currently unused)
#   <report.yaml>  report_affected.py --output-format yaml output
#
# Output: CycloneDX VEX JSON on stdout. Requires python3 + PyYAML.
# If unipi-kernel is absent from the SBOM, an empty VEX is emitted (no-op).
#
# NB on affects[].ref: DependencyTrack's VEX importer resolves the ref against
# the project's metadata.component bom-ref, but does NOT resolve per-component
# bom-refs (it doesn't persist component bom-refs, so purl-shaped refs are
# "not resolvable" and silently skipped — see DependencyTrack #5260). We
# therefore point affects[].ref at the SBOM's metadata.component (project)
# bom-ref, which scopes the analysis to the whole project. This is the same
# pattern used by the working example in DependencyTrack discussion #1921.

import json
import os
import sys


def load_report(path):
    """Parse report_affected.py yaml output -> (affected, fixed, ignored) sets.

    The yaml is `{branch_full_name: {affected: [...], fixed: [...], ignored: [...]}}`.
    We take the first (only) branch entry.
    """
    try:
        import yaml  # type: ignore
    except ImportError:
        sys.exit("gen-vex: PyYAML required (python3-yaml) to parse "
                 "report_affected.py output")
    with open(path) as f:
        data = yaml.safe_load(f)
    if not data:
        return set(), set(), set()
    branch = next(iter(data.values()))
    to_set = lambda key: {c.upper() for c in (branch.get(key) or [])}
    return to_set("affected"), to_set("fixed"), to_set("ignored")


def component_ref(cdx):
    """bom-ref to scope VEX analyses to.

    DependencyTrack resolves the project's metadata.component bom-ref, not
    per-component bom-refs (those are not persisted and yield 'Unable to locate
    affected element'). Use the project bom-ref so suppressions actually apply.
    We still require a unipi-kernel component to exist (otherwise the image
    has no kernel to VEX) but point affects at the project, not the component.
    """
    has_kernel = any(c.get("name") == "unipi-kernel"
                     for c in cdx.get("components", []))
    if not has_kernel:
        return None
    return cdx.get("metadata", {}).get("component", {}).get("bom-ref")


def main():
    if len(sys.argv) != 4:
        sys.exit("usage: gen-vex.py <cdx.json> <sbom-rootfs> <report.yaml>")
    cdx_path, _rootfs, report_path = sys.argv[1:4]

    with open(cdx_path) as f:
        cdx = json.load(f)

    ref = component_ref(cdx)
    if ref is None:
        json.dump(_empty_vex(cdx), sys.stdout, indent=2)
        print()
        return

    affected, fixed, ignored = load_report(report_path)

    vulns = []
    for cve in sorted(fixed):
        vulns.append(_entry(cve, ref, state="resolved",
                           detail="Fixed (backported) on the CIP SLTS branch "
                                  "per cip-kernel-sec; no action required."))
    for cve in sorted(ignored):
        vulns.append(_entry(cve, ref, state="not_affected",
                           detail="Marked not-applicable/ignored on the CIP "
                                  "SLTS branch per cip-kernel-sec."))

    vex = _empty_vex(cdx)
    vex["vulnerabilities"] = vulns
    vex["metadata"]["tools"] = {
        "components": [{
            "type": "application",
            "name": "cip-kernel-sec",
            "externalReferences": [{
                "type": "website",
                "url": "https://gitlab.com/cip-project/cip-kernel/cip-kernel-sec",
            }],
        }]
    }
    json.dump(vex, sys.stdout, indent=2)
    print()


def _entry(cve, ref, state, detail):
    return {
        "id": cve,
        "source": {
            "name": "NVD",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
        },
        "analysis": {
            "state": state,
            "response": ["will_not_fix"],
            "detail": detail,
        },
        "affects": [{"ref": ref}],
    }


def _empty_vex(cdx):
    md = cdx.get("metadata", {})
    comp = md.get("component", {})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
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
