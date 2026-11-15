#!/usr/bin/env bash
# Build Helm RPMs natively on Rocky/RHEL 9 or 10.
# Output: out/helm-rdp-<ver>-1.elN.noarch.rpm, .src.rpm and helm-rdp-<ver>.tar.gz
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' helm_rdp/__init__.py)"
command -v rpmbuild >/dev/null 2>&1 || {
    echo "rpmbuild not found. Install it:  sudo dnf install -y rpm-build python3 desktop-file-utils python3-cryptography python3-gobject-base libsecret" >&2
    exit 1
}
TOP="$(mktemp -d)"
trap 'rm -rf "${TOP}"' EXIT
mkdir -p "${TOP}"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS} out
tar --exclude=.git --exclude=out --exclude='__pycache__' --exclude='*.pyc' \
    --transform "s,^,helm-rdp-${VERSION}/," \
    -czf "${TOP}/SOURCES/helm-rdp-${VERSION}.tar.gz" \
    helm_rdp bin packaging tests docs README.md HELP.md LICENSE .gitignore build.sh
cp "${TOP}/SOURCES/helm-rdp-${VERSION}.tar.gz" out/
rpmbuild -ba --define "_topdir ${TOP}" packaging/helm-rdp.spec
cp -v "${TOP}"/RPMS/noarch/helm-rdp-*.rpm "${TOP}"/SRPMS/helm-rdp-*.src.rpm out/
