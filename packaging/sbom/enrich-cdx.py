#!/usr/bin/env python3
# Enrich the CycloneDX SBOM produced by 'trivy rootfs' with component
# provenance, CPE, pedigree, supplier, and origin metadata.
#
# Trivy emits deb components with purl and supplier but no CPE, no
# pedigree, and no provenance. This script merges data from per-package
# component SBOMs (component.cdx.json) that Unipi .debs install under
# /usr/share/doc/<pkg>/, and applies three independent enrichment passes:
#
# 1. Component merge (per package with a component.cdx.json):
#    - CPE for NVD vulnerability matching (kernel: linux_kernel, u-boot: denx:u-boot)
#    - Pedigree: ancestors, patches, commits, notes — the fork lineage
#    - Component type (operating-system, firmware, application) — trivy
#      emits "library" for all debs; the component SBOM carries the
#      semantically correct type
#    - Dependency edges (pip graph from evok venv, etc.)
#    - External references (advisory feeds, VCS, website)
#
# 2. Supplier rewrite (Unipi-owned components only):
#    Trivy flattens the deb Maintainer into supplier.name as
#    "<person> <user@domain>". We rewrite supplier to the org ("Unipi")
#    and move the maintainer into supplier.contact so DependencyTrack
#    displays the organization, not the individual packager.
#
# 3. Origin tagging (all components):
#    Every component gets a `unipi:origin` property ("unipi" or "debian")
#    so downstream tooling can select the Unipi-owned subset for
#    per-package treatment without re-deriving from supplier.name.
#
# Unipi-owned packages are identified by name prefix ("unipi-") or the
# ORIGIN_EXTRA list (evok, evok-unipi-data, evok-web, etc.) or by
# supplier email domain. All identifiers are env-overridable.
#
# Purl namespace rewrite: Unipi-owned deb purls are rewritten from
# pkg:deb/debian/<name> to pkg:deb/unipi/<name> so DependencyTrack
# groups them under the Unipi namespace.
#
# Usage: enrich-cdx.py <cdx.json> <sbom-rootfs>
#   discovers component.cdx.json files in <sbom-rootfs>/usr/share/doc/*/
#   rewrites <cdx.json> in place.

import json
import os
import re
import sys
from typing import Any

ORIGIN_DOMAIN = os.environ.get("UNIPI_ORIGIN_DOMAIN", "unipi.technology")
ORIGIN_PREFIX = os.environ.get("UNIPI_ORIGIN_PREFIX", "unipi-")
ORIGIN_SUPPLIER = os.environ.get("UNIPI_ORIGIN_SUPPLIER", "Unipi")
ORIGIN_NAMESPACE = os.environ.get("UNIPI_ORIGIN_NAMESPACE", "unipi")
ORIGIN_EXTRA = [
    n.strip() for n in os.environ.get(
        "UNIPI_ORIGIN_EXTRA", "evok,evok-unipi-data,evok-web,evok-builder"
    ).split(",") if n.strip()
]


def origin_of(comp: dict[str, Any]) -> str:
    """Return 'unipi' or 'debian' for a component."""
    name = comp.get("name", "")
    if name.startswith(ORIGIN_PREFIX) or name in ORIGIN_EXTRA:
        return "unipi"
    supplier = (comp.get("supplier") or {}).get("name", "")
    m = re.search(r"<([^>]*@([^>]*))>", supplier)
    if m and m.group(2).lower() == ORIGIN_DOMAIN.lower():
        return "unipi"
    return "debian"


def set_origin(comp: dict[str, Any], origin: str) -> None:
    """Set the unipi:origin property, adding or updating it."""
    props = comp.setdefault("properties", [])
    for p in props:
        if p.get("name") == "unipi:origin":
            p["value"] = origin
            return
    props.append({"name": "unipi:origin", "value": origin})


def set_supplier(comp: dict[str, Any], org: str) -> None:
    """Set the CycloneDX `supplier.name` to the org so DT's UI shows
    "Unipi" for the 14 Unipi components instead of the human maintainer.
    The original maintainer string Trivy flattened into supplier.name as
    "Name <user@domain>" is split back into name/email and preserved as a
    supplier.contact entry (an array of OrganizationalContact per the
    CycloneDX schema), so DT renders the email in its own field rather
    than jammed into the name. CycloneDX's supplier is the organization
    that supplied the component — for these debs that's Unipi, not the
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


def reparent_unipi_packages(cdx: dict[str, Any], name_prefix: str) -> None:
    """Trivy wires every package under an `operating-system` node
    (root -> debian -> [all packages]). Reparent the Unipi-owned
    packages to the root directly so the graph reads:
        root -> debian  -> [249 debian packages]
        root -> unipi-*  [14 unipi packages directly]
    The OS node is preserved (it carries distro provenance and the
    debian package layer). The Unipi packages are pulled out of the
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
    # Identify the Unipi package bom-refs (by name prefix or extra names).
    unipi_refs = {
        c.get("bom-ref") for c in cdx.get("components", [])
        if c.get("name", "").startswith(name_prefix)
        or c.get("name", "") in ORIGIN_EXTRA
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


def rewrite_purl_namespace(cdx: dict[str, Any], name_prefix: str, new_namespace: str) -> None:
    """Rewrite the purl namespace of Unipi-owned components from
    pkg:deb/debian/<name> to pkg:deb/<new_namespace>/<name>, and update
    every reference to the old purl (the component's bom-ref, which
    Trivy sets equal to the purl, and every dependency ref / dependsOn
    entry) so the graph stays consistent.

    Dependency-Track groups components by purl namespace in its
    dependency graph. Trivy derives the namespace from the apt distro
    suite, so every deb reads as pkg:deb/debian/... and groups under
    "debian" — making the ~14 Unipi components indistinguishable from
    the 250 Debian ones. These are Unipi packages packaged as debs,
    not Debian packages, so the "unipi" namespace is semantically
    correct. CVE matching is unaffected: the kernel matches via CPE,
    and the other Unipi packages have no Debian security advisories."""
    prefix_purl = "pkg:deb/debian/"
    # Build the old->new mapping for every affected component.
    remap: dict[str, str] = {}
    for comp in cdx.get("components", []):
        purl = comp.get("purl") or ""
        bomref = comp.get("bom-ref") or ""
        name = comp.get("name", "")
        is_unipi = name.startswith(name_prefix) or name in ORIGIN_EXTRA
        if is_unipi and purl.startswith("pkg:deb/debian/"):
            new_purl = purl.replace("pkg:deb/debian/", f"pkg:deb/{new_namespace}/", 1)
            remap[purl] = new_purl
            if bomref and bomref != purl:
                new_bomref = bomref.replace("pkg:deb/debian/", f"pkg:deb/{new_namespace}/", 1)
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


def enrich_component(comp: dict[str, Any], src: dict[str, Any]) -> None:
    """Inject CPE, pedigree, type, and advisory refs into an image-SBOM
    component from a provenance source. The source can be:
      - A flat upstream-metadata.json dict (custom format): has
        top-level cpe, ancestors, patches, build_commit, notes
      - A CycloneDX component object (from component.cdx.json): has
        top-level cpe, and ancestors/patches/commits/notes under
        pedigree
    Both shapes are normalized to the flat form before applying."""
    # Normalize: if the source is a CycloneDX component (has pedigree),
    # extract the flat fields from it.
    if "pedigree" in src:
        ped = src["pedigree"]
        meta: dict[str, Any] = {
            "cpe": src.get("cpe", ""),
            "ancestors": ped.get("ancestors", []),
            "patches": ped.get("patches", []),
            "build_commit": (ped.get("commits", [{}])[0].get("uid", "") if ped.get("commits") else ""),
            "notes": ped.get("notes", ""),
        }
        # Ancestors in CycloneDX already have type/purl/externalReferences;
        # convert to the flat format (repository/homepage strings).
        flat_ancestors: list[dict[str, Any]] = []
        for a in meta["ancestors"]:
            fa: dict[str, Any] = {"name": a["name"], "version": a["version"]}
            if a.get("purl"):
                fa["purl"] = a["purl"]
            for ref in a.get("externalReferences", []):
                if ref.get("type") == "vcs":
                    fa["repository"] = ref["url"]
                elif ref.get("type") == "website":
                    fa["homepage"] = ref["url"]
                elif ref.get("type") == "distribution":
                    fa["repository"] = ref["url"]
            flat_ancestors.append(fa)
        meta["ancestors"] = flat_ancestors
        # Patches in CycloneDX are [{"type": "unofficial"}, ...] — convert
        # to a count-based list for the notes, then re-expand below.
        if isinstance(meta["patches"], list) and meta["patches"] and isinstance(meta["patches"][0], dict):
            meta["_cdx_patches"] = meta["patches"]
            meta["patches"] = []
    else:
        meta = src

    # CPE: use the source's cpe field if present, otherwise derive
    # from the linux ancestor version (kernel).
    cpe = meta.get("cpe", "")
    if not cpe:
        for a in meta.get("ancestors", []):
            if a.get("name") == "linux":
                base_ver = a.get("version", "")
                if base_ver:
                    cpe = f"cpe:2.3:o:linux:linux_kernel:{base_ver}:*:*:*:*:*:*:*"
                break
    if cpe:
        comp["cpe"] = cpe

    # Preserve the component SBOM's type (e.g. operating-system, firmware,
    # application) — trivy emits "library" for all debs, but the component
    # SBOM carries the semantically correct type.
    src_type = src.get("type")
    if src_type:
        comp["type"] = src_type

    # Pedigree.ancestors: CycloneDX Component objects (need a `type`);
    # convert the flat metadata's repository/homepage strings into
    # externalReferences entries.
    ancestors: list[dict[str, Any]] = []
    for a in meta.get("ancestors", []):
        anc: dict[str, Any] = {"type": "library", "name": a["name"], "version": a["version"]}
        if a.get("purl"):
            anc["purl"] = a["purl"]
        extrefs: list[dict[str, Any]] = []
        if a.get("repository"):
            extrefs.append({"type": "vcs", "url": a["repository"]})
        if a.get("homepage"):
            extrefs.append({"type": "website", "url": a["homepage"]})
        if extrefs:
            anc["externalReferences"] = extrefs
        ancestors.append(anc)

    pedigree: dict[str, Any] = {"ancestors": ancestors}

    # Build commit -> pedigree.commits.
    commit = meta.get("build_commit", "")
    if commit:
        pedigree["commits"] = [{"uid": commit}]

    # Patchset -> pedigree.patches. The kernel's flat metadata has a
    # list of patch names; u-boot has a dict with sub-project keys.
    # A CycloneDX source already has [{"type": "unofficial"}, ...].
    if meta.get("_cdx_patches"):
        pedigree["patches"] = meta["_cdx_patches"]
    else:
        raw_patches = meta.get("patches", [])
        if isinstance(raw_patches, dict):
            all_patches = []
            for sub_patches in raw_patches.values():
                all_patches.extend(sub_patches)
        else:
            all_patches = raw_patches
        if all_patches:
            pedigree["patches"] = [{"type": "unofficial"} for _ in all_patches]

    # Notes: use the source's notes field if present, else generate.
    notes = meta.get("notes", "")
    if notes:
        pedigree["notes"] = notes

    comp["pedigree"] = pedigree

    # Advisories feed as a component-level external reference.
    advisories = meta.get("advisories", "")
    if advisories:
        extrefs = comp.setdefault("externalReferences", [])
        if not any(e.get("url") == advisories for e in extrefs):
            extrefs.append({"type": "advisories", "url": advisories})


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit("usage: enrich-cdx.py <cdx.json> <sbom-rootfs>")
    cdx_path = sys.argv[1]
    rootfs = sys.argv[2]

    with open(cdx_path) as f:
        cdx: dict[str, Any] = json.load(f)

    # Component-specific enrichment from CycloneDX component SBOMs that
    # .debs install at /usr/share/doc/<pkg>/component.cdx.json.
    # Discovery is by file presence — any package that ships a
    # component.cdx.json is enriched, not just unipi-* prefixed ones.
    META_DIR = os.path.join(rootfs, "usr/share/doc")
    if os.path.isdir(META_DIR):
        for pkg_dir_name in sorted(os.listdir(META_DIR)):
            meta_path = os.path.join(META_DIR, pkg_dir_name, "component.cdx.json")
            if not os.path.exists(meta_path):
                continue
            with open(meta_path) as f:
                meta: dict[str, Any] = json.load(f)
            if not isinstance(meta, dict) or meta.get("bomFormat") != "CycloneDX":
                continue
            existing_refs: set[str] = {c.get("bom-ref", "") for c in cdx.get("components", [])}
            # The component SBOM's subject lives in metadata.component
            # (CycloneDX canonical) — enrich the matching image-SBOM
            # component from it, then process the dependencies list.
            src_subjects = []
            md_comp = meta.get("metadata", {}).get("component")
            if md_comp:
                src_subjects.append(md_comp)
            src_subjects.extend(meta.get("components", []))
            for src_comp in src_subjects:
                src_ref = src_comp.get("bom-ref", "")
                existing: dict[str, Any] | None = None
                if src_ref and src_ref in existing_refs:
                    existing = next(c for c in cdx.get("components", []) if c.get("bom-ref") == src_ref)
                else:
                    comp_name = src_comp.get("name", "")
                    if comp_name:
                        existing = next((c for c in cdx.get("components", []) if c.get("name") == comp_name), None)
                if existing is not None:
                    enrich_component(existing, src_comp)
                elif src_ref and src_ref not in existing_refs and src_comp is not md_comp:
                    cdx.setdefault("components", []).append(src_comp)
                    existing_refs.add(src_ref)
            # Merge dependency edges from the component SBOM. For edges
            # whose ref already exists in the image SBOM, union the
            # dependsOn lists (trivy's deb->deb edges + component SBOM's
            # pip edges). For new edges, add them.
            dep_index: dict[str, set[str]] = {}
            for d in cdx.get("dependencies", []):
                dep_index.setdefault(d.get("ref", ""), set()).update(d.get("dependsOn", []))
            for src_dep in meta.get("dependencies", []):
                src_dep_ref = src_dep.get("ref", "")
                if src_dep_ref in existing_refs:
                    dep_index.setdefault(src_dep_ref, set()).update(src_dep.get("dependsOn", []))
            cdx["dependencies"] = [{"ref": ref, "dependsOn": sorted(deps)}
                                   for ref, deps in dep_index.items()]

    # Tag every component with its origin (unipi vs debian) so downstream
    # tooling can select the Unipi-owned subset, and set `supplier` on the
    # Unipi components to the org so DT's UI shows "Unipi" instead of the
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
        # DT derives the project classifier from metadata.component.type
        # during async BOM processing (ModelConverter.convertToProject),
        # which clobbers any classifier set via the PATCH API. Trivy emits
        # "application" here; force "operating-system" so DT assigns
        # OPERATING_SYSTEM itself. See DT #4352.
        md_comp["type"] = "operating-system"
    # Reparent Unipi packages to the root alongside the OS node, so the
    # graph reads: root -> debian -> [249 debian packages], root ->
    # [14 unipi packages]. Trivy wires everything under the OS node;
    # groupings (debian vs unipi) instead of one. Must run before the
    # purl namespace rewrite so the reparenting sees the original refs.
    reparent_unipi_packages(cdx, ORIGIN_PREFIX)

    # Rewrite the purl namespace of Unipi-owned components from
    # pkg:deb/debian/unipi-* to pkg:deb/unipi/unipi-* (and their bom-ref,
    # which Trivy sets equal to the purl, and every dependency reference).
    # DT groups components by purl namespace in its dependency graph; with
    # the "debian" namespace all 264 debs read as "from debian". Using the
    # "unipi" namespace makes the ~14 Unipi components group under their
    # own vendor. This is semantically correct: these are Unipi packages
    # packaged as debs, not Debian packages. CVE matching is unaffected
    # (the kernel matches via CPE, the rest have no Debian advisories).
    rewrite_purl_namespace(cdx, ORIGIN_PREFIX, ORIGIN_NAMESPACE)

    with open(cdx_path, "w") as f:
        json.dump(cdx, f, indent=2)


if __name__ == "__main__":
    main()
