#!/usr/bin/env python3
# Enrich a CycloneDX or SPDX SBOM with per-file SHA-256 hashes of every
# installed component, read from the extracted rootfs's dpkg database.
#
# Why: BSI TR-03183-2 §5.2.2 requires the SHA-256 of the executable form of
# each component "on a mass storage device". Trivy does not emit component
# hashes. This step derives them from the installed files recorded by dpkg.
#
# Source of truth: <rootfs>/var/lib/dpkg/info/<package>.list (the dpkg
# installed-file list per package). Directories and symlinks are skipped;
# only regular files are hashed (their content, following symlinks). Missing
# files are skipped (e.g. conffiles removed by the user).
#
# Component matching: by package name. The SBOM component's name (CycloneDX)
# or package name (SPDX) matches the dpkg <package>.list basename. The purl
# is not needed; dpkg package names are unique in a single rootfs.
#
# Per format:
#   CycloneDX 1.5+: for each hashed file, a property is added to the
#     component:
#       { "name": "unipi:fileHash:sha256", "value": "<path> <sha256>" }
#     (Multiple properties with the same name are allowed by the spec.)
#   SPDX 2.3: the package gets filesAnalyzed=true, a packageVerificationCode
#     (per SPDX spec: SHA1 over the sorted SHA1 digests of the package's
#     files), and each file is added to the top-level `files` array with a
#     SHA-256 checksum, plus a CONTAINS relationship from the package to the
#     file.
#
# Usage: enrich-hashes.py <sbom.json> <sbom-rootfs>
#   rewrites <sbom.json> in place. No-op (rewrites unchanged) if the dpkg
#   database is absent.
#
# Requires: python3 only (hashlib is stdlib).

import hashlib
import json
import os
import sys

DPKG_INFO = "var/lib/dpkg/info"
HASH_PROP = "unipi:fileHash:sha256"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def sha1_file(path):
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def list_files_for_pkg(rootfs, pkg):
    """Return the regular files (absolute, rootfs-relative) installed by pkg."""
    lst = os.path.join(rootfs, DPKG_INFO, pkg + ".list")
    if not os.path.exists(lst):
        return []
    files = []
    with open(lst) as f:
        for line in f:
            p = line.strip()
            if not p or p == "/.":
                continue
            # dpkg lists dirs and symlinks too; keep only regular files.
            full = os.path.join(rootfs, p.lstrip("/"))
            try:
                if os.path.isfile(full) and not os.path.islink(full):
                    files.append(p)
            except OSError:
                continue
    return files


def hash_files(rootfs, paths):
    """Return [(path, sha256, sha1)] for files that exist; skip missing."""
    out = []
    for p in paths:
        full = os.path.join(rootfs, p.lstrip("/"))
        try:
            out.append((p, sha256_file(full), sha1_file(full)))
        except OSError:
            continue  # file removed (e.g. conffile) -> skip
    return out


def pkg_verification_code(sha1s):
    """SPDX packageVerificationCode: SHA1 over concatenation of sorted SHA1
    digests of the package's files (excluding the SPDX document itself)."""
    joined = "".join(sorted(sha1s))
    return hashlib.sha1(joined.encode()).hexdigest()


def enrich_cyclonedx(doc, rootfs):
    comps = doc.get("components", [])
    for c in comps:
        name = c.get("name")
        if not name:
            continue
        paths = list_files_for_pkg(rootfs, name)
        if not paths:
            continue
        hashes = hash_files(rootfs, paths)
        if not hashes:
            continue
        props = c.setdefault("properties", [])
        for path, sha256, _ in hashes:
            props.append({"name": HASH_PROP, "value": f"{path} {sha256}"})
    return doc


def enrich_spdx(doc, rootfs):
    packages = doc.get("packages", [])
    files = doc.setdefault("files", [])
    rels = doc.setdefault("relationships", [])
    existing_spdxids = {f.get("SPDXID") for f in files}
    existing_rels = {(r.get("spdxElementId"), r.get("relationshipType"),
                      r.get("relatedSpdxElement")) for r in rels}
    for pkg in packages:
        name = pkg.get("name")
        if not name:
            continue
        paths = list_files_for_pkg(rootfs, name)
        if not paths:
            continue
        hashes = hash_files(rootfs, paths)
        if not hashes:
            continue
        pkg_spdxid = pkg.get("SPDXID")
        sha1s = []
        for path, sha256, sha1 in hashes:
            fid = f"SPDXRef-File-{abs(hash(path)) % (10**12)}"
            # ensure unique SPDXID across the document
            base, n = fid, 1
            while fid in existing_spdxids:
                fid = f"{base}-{n}"; n += 1
            existing_spdxids.add(fid)
            files.append({
                "SPDXID": fid,
                "fileName": path,
                "checksums": [{"algorithm": "SHA256", "checksumValue": sha256}],
            })
            rel_key = (pkg_spdxid, "CONTAINS", fid)
            if rel_key not in existing_rels:
                rels.append({
                    "spdxElementId": pkg_spdxid,
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": fid,
                })
                existing_rels.add(rel_key)
            sha1s.append(sha1)
        pkg["filesAnalyzed"] = True
        pkg["packageVerificationCode"] = {
            "packageVerificationCodeValue": pkg_verification_code(sha1s),
        }
    return doc


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: enrich-hashes.py <sbom.json> <sbom-rootfs>")
    sbom_path, rootfs = sys.argv[1:2 + 1]
    if not os.path.isdir(os.path.join(rootfs, DPKG_INFO)):
        # no dpkg database -> nothing to do
        return
    with open(sbom_path) as f:
        doc = json.load(f)
    if doc.get("bomFormat") == "CycloneDX":
        doc = enrich_cyclonedx(doc, rootfs)
    elif "spdxVersion" in doc:
        doc = enrich_spdx(doc, rootfs)
    else:
        sys.exit("enrich-hashes: unrecognized SBOM format")
    with open(sbom_path, "w") as f:
        json.dump(doc, f, indent=2)


if __name__ == "__main__":
    main()
