#!/bin/bash

timestamp=$(date --utc "+%y%m%d%H%M")

git_hash=$(git rev-parse --verify HEAD)
if [ ! -z "$(git status --untracked-files=no --porcelain)" ]
then
  git_hash="${git_hash}+"
fi

echo -n 0.0."${timestamp}~${git_hash}"
