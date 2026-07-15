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
# image) the kernel enrichment is skipped, but origin tagging (below)
# still runs, so the build never fails.
#
# In addition, every component is tagged with a `unipi:origin` property
# (value `unipi` or `debian`) so downstream tooling can select the UniPi-
# owned subset (~14 components) for per-package treatment. This pass is
# independent of the kernel metadata and always runs.
#
# Usage: enrich-cdx.py <cdx.json> <sbom-rootfs>
#   reads  <sbom-rootfs>/usr/share/doc/unipi-kernel/upstream-metadata.json
#   rewrites <cdx.json> in place.

import json
import os
import re
import sys

META_PATH = "usr/share/doc/unipi-kernel/upstream-metadata.json"

# Origin tagging: distinguish UniPi-owned components from Debian ones so
# downstream tooling can select the ~14 UniPi components for per-package
# treatment without re-deriving from supplier.name. A component is
# 'unipi' if its maintainer email domain is the UniPi domain OR its name
# follows the unipi-* naming convention; otherwise 'debian'.
#
# The email lives inside supplier.name as "<name> <user@domain>" (Trivy
# flattens the deb Maintainer field into a single string). Both the domain
# and the prefix are env-overridable so nothing is truly hardcoded — a build
# may point at a different org domain without editing this script.
#
# Supplier: Trivy flattens the deb Maintainer field into supplier.name as
# "<person> <user@domain>". Dependency-Track 5.0.2 surfaces supplier.name
# in its UI (it does not render `publisher` despite storing it), so a
# UniPi deb shows as "Miroslav Ondra <ondra@faster.cz>" — indistinguishable
# from a glance at Debian components. We rewrite supplier to name the
# org ("UniPi") and move the human maintainer into supplier.contact, so
# DT displays "UniPi" while the maintainer is preserved. CycloneDX's
# supplier is the organization that supplied the component — which for
# these debs is UniPi, not the individual packager.
ORIGIN_DOMAIN = os.environ.get("UNIPI_ORIGIN_DOMAIN", "unipi.technology")
ORIGIN_PREFIX = os.environ.get("UNIPI_ORIGIN_PREFIX", "unipi-")
ORIGIN_SUPPLIER = os.environ.get("UNIPI_ORIGIN_SUPPLIER", "UniPi")
ORIGIN_NAMESPACE = os.environ.get("UNIPI_ORIGIN_NAMESPACE", "unipi")


def origin_of(comp):
    """Return 'unipi' or 'debian' for a component."""
    name = comp.get("name", "")
    if name.startswith(ORIGIN_PREFIX):
        return "unipi"
    supplier = (comp.get("supplier") or {}).get("name", "")
    m = re.search(r"<([^>]*@([^>]*))>", supplier)
    if m and m.group(2).lower() == ORIGIN_DOMAIN.lower():
        return "unipi"
    return "debian"


def set_origin(comp, origin):
    """Set the unipi:origin property, updating an existing one if present."""
    props = comp.setdefault("properties", [])
    for p in props:
        if p.get("name") == "unipi:origin":
            p["value"] = origin
            return
def set_supplier(comp, org):
    """Set the CycloneDX `supplier.name` to the org so DT's UI shows
    "UniPi" for the 14 UniPi components instead of the human maintainer.
    The original maintainer string Trivy flattened into supplier.name as
    "Name <user@domain>" is split back into name/email and preserved as a
    supplier.contact entry (an array of OrganizationalContact per the
    CycloneDX schema), so DT renders the email in its own field rather
    than jammed into the name. CycloneDX's supplier is the organization
    that supplied the component — for these debs that's UniPi, not the
    individual packager."""
    sup = comp.get("supplier") or {}
    prev = sup.get("name")
    if prev and prev != org:
        m = re.match(r"\s*(.*?)\s*<([^>]*)>\s*$", prev)
        if m:
            sup["contact"] = [{"name": m.group(1), "email": m.group(2)}]
        else:
            sup["contact"] = [{"name": prev}]
    sup["name"] = org
    comp["supplier"] = sup


def reparent_unipi_packages(cdx, name_prefix):
    """Trivy wires every package under an `operating-system` node
    (root -> debian -> [all packages]). Reparent the UniPi-owned
    packages to the root directly so the graph reads:
        root -> debian  -> [249 debian packages]
        root -> unipi-*  [14 unipi packages directly]
    The OS node is preserved (it carries distro provenance and the
    debian package layer). The UniPi packages are pulled out of the
    OS node's dependsOn and added to the root's dependsOn alongside
    the OS ref, giving two parallel groupings: debian vs unipi."""
    root_ref = (cdx.get("metadata", {}).get("component") or {}).get("bom-ref")
    if not root_ref:
        return
    os_refs = {
        c.get("bom-ref") for c in cdx.get("components", [])
        if c.get("type") == "operating-system"
    }
    if not os_refs:
        return
    # Identify the UniPi package bom-refs (by name prefix).
    unipi_refs = {
        c.get("bom-ref") for c in cdx.get("components", [])
        if c.get("name", "").startswith(name_prefix)
    }
    if not unipi_refs:
        return
    deps = cdx.get("dependencies", [])
    # Remove unipi refs from every OS node's dependsOn.
    for d in deps:
        if d.get("ref") in os_refs:
            d["dependsOn"] = [dep for dep in d.get("dependsOn", []) if dep not in unipi_refs]
    # Add the unipi refs to the root's dependsOn, alongside the OS refs.
    for d in deps:
        if d.get("ref") == root_ref:
            cur = set(d.get("dependsOn", []))
            cur.update(unipi_refs)
            d["dependsOn"] = sorted(cur)
            break


def rewrite_purl_namespace(cdx, name_prefix, new_namespace):
    """Rewrite the purl namespace of UniPi-owned components from
    pkg:deb/debian/<name> to pkg:deb/<new_namespace>/<name>, and update
    every reference to the old purl (the component's bom-ref, which
    Trivy sets equal to the purl, and every dependency ref / dependsOn
    entry) so the graph stays consistent.

    Dependency-Track groups components by purl namespace in its
    dependency graph. Trivy derives the namespace from the apt distro
    suite, so every deb reads as pkg:deb/debian/... and groups under
    "debian" — making the ~14 UniPi components indistinguishable from
    the 250 Debian ones. These are UniPi packages packaged as debs,
    not Debian packages, so the "unipi" namespace is semantically
    correct. CVE matching is unaffected: the kernel matches via CPE,
    and the other UniPi packages have no Debian security advisories."""
    prefix_purl = f"pkg:deb/debian/{name_prefix}"
    prefix_bomref = prefix_purl
    # Build the old->new mapping for every affected component.
    remap = {}
    for comp in cdx.get("components", []):
        purl = comp.get("purl") or ""
        bomref = comp.get("bom-ref") or ""
        name = comp.get("name", "")
        if name.startswith(name_prefix) and purl.startswith(prefix_purl):
            new_purl = purl.replace(prefix_purl, f"pkg:deb/{new_namespace}/{name_prefix}", 1)
            remap[purl] = new_purl
            if bomref and bomref != purl:
                new_bomref = bomref.replace(prefix_bomref, f"pkg:deb/{new_namespace}/{name_prefix}", 1)
                remap[bomref] = new_bomref
    if not remap:
        return
    # Apply to components.
    for comp in cdx.get("components", []):
        if comp.get("purl") in remap:
            comp["purl"] = remap[comp["purl"]]
        bomref = comp.get("bom-ref")
        if bomref in remap:
            comp["bom-ref"] = remap[bomref]
    # Apply to dependencies (ref + dependsOn).
    for d in cdx.get("dependencies", []):
        if d.get("ref") in remap:
            d["ref"] = remap[d["ref"]]
        d["dependsOn"] = [remap.get(dep, dep) for dep in d.get("dependsOn", [])]
    # Apply to metadata.component bom-ref if present.
    md = cdx.get("metadata", {}).get("component", {}) or {}
    if md.get("bom-ref") in remap:
        md["bom-ref"] = remap[md["bom-ref"]]


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: enrich-cdx.py <cdx.json> <sbom-rootfs>")

    cdx_path = sys.argv[1]
    rootfs = sys.argv[2]
    meta_path = os.path.join(rootfs, META_PATH)

    with open(cdx_path) as f:
        cdx = json.load(f)

    # Kernel-specific enrichment (CPE, pedigree) needs the upstream metadata
    # the unipi-kernel .deb installs. If absent (older deb / non-kernel
    # image) the kernel block is skipped — but origin tagging below still
    # runs, independent of metadata.
    meta = None
    if os.path.exists(meta_path):
        with open(meta_path) as f:
            meta = json.load(f)

    if meta is not None:
        components = cdx.get("components", [])
        comp = next((c for c in components if c.get("name") == "unipi-kernel"), None)
        if comp is not None:
            enrich_kernel(comp, meta)

    # Tag every component with its origin (unipi vs debian) so downstream
    # tooling can select the UniPi-owned subset, and set `supplier` on the
    # UniPi components to the org so DT's UI shows "UniPi" instead of the
    # human maintainer (DT 5.0.2 renders supplier.name; publisher is not
    # displayed despite being stored). Debian components keep their
    # maintainer supplier — they correctly read as Debian upstream.
    for c in cdx.get("components", []):
        origin = origin_of(c)
        set_origin(c, origin)
        if origin == "unipi":
            set_supplier(c, ORIGIN_SUPPLIER)
    md_comp = cdx.get("metadata", {}).get("component")
    if md_comp:
        set_origin(md_comp, origin_of(md_comp))

    # Reparent UniPi packages to the root alongside the OS node, so the
    # graph reads: root -> debian -> [249 debian packages], root ->
    # [14 unipi packages]. Trivy wires everything under the OS node;
    # groupings (debian vs unipi) instead of one. Must run before the
    # purl namespace rewrite so the reparenting sees the original refs.
    reparent_unipi_packages(cdx, ORIGIN_PREFIX)

    # Rewrite the purl namespace of UniPi-owned components from
    # pkg:deb/debian/unipi-* to pkg:deb/unipi/unipi-* (and their bom-ref,
    # which Trivy sets equal to the purl, and every dependency reference).
    # DT groups components by purl namespace in its dependency graph; with
    # the "debian" namespace all 264 debs read as "from debian". Using the
    # "unipi" namespace makes the ~14 UniPi components group under their
    # own vendor. This is semantically correct: these are UniPi packages
    # packaged as debs, not Debian packages. CVE matching is unaffected
    # (the kernel matches via CPE, the rest have no Debian advisories).
    rewrite_purl_namespace(cdx, ORIGIN_PREFIX, ORIGIN_NAMESPACE)

    with open(cdx_path, "w") as f:
        json.dump(cdx, f, indent=2)


def enrich_kernel(comp, meta):
    """Inject CPE, pedigree, and advisory refs into the unipi-kernel comp."""
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


if __name__ == "__main__":
    main()
