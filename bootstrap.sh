#!/bin/bash
set -e
set -x

cat > debian/changelog <<EOF
zdma-dkms ($(./print-version.sh)) bionic; urgency=medium

  * Deployment.

 -- Bryce Hathaway <bhathaway@zendar.io>  $(date -u)
EOF

cat debian/changelog

rm -rf build
mkdir build
cp -r src build/
cp -r debian build/
cd build

dpkg-buildpackage -us -uc

ls ../
