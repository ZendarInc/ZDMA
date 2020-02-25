#!/bin/bash
set -e
set -x

cat > debian/changelog <<EOF
zdma-dkms ($(./print-version.sh)) bionic; urgency=medium

  * Deployment.

 -- Christopher Hanks  <chris@zendar.io>  $(date -u)
EOF

cat debian/changelog

mkdir build
cd build
cp -r src build/
cp -r debian build/

dpkg-buildpackage -us -uc

ls ../
