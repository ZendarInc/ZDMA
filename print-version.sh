#!/bin/bash

root=$(dirname ${0})

major=$(grep DRV_MOD_MAJOR      ${root}/src/version.h)
minor=$(grep DRV_MOD_MINOR      ${root}/src/version.h)
patch=$(grep DRV_MOD_PATCHLEVEL ${root}/src/version.h)

major=$(echo ${major} | awk '{print $3}')
minor=$(echo ${minor} | awk '{print $3}')
patch=$(echo ${patch} | awk '{print $3}')
echo "${major}.${minor}.${patch}"
