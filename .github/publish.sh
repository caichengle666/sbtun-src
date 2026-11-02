#!/usr/bin/env bash
# 源码仓库是私有的，安装包发布到公开仓库 caichengle666/sbtun：
# 把文件放进 incoming/ 作为一个临时分支推过去（deploy key），公开仓库的工作流据此创建/更新 Release 并删掉分支。
# 用法：bash .github/publish.sh 文件...
set -euo pipefail
: "${RELEASE_DEPLOY_KEY:?缺少 RELEASE_DEPLOY_KEY}"
tag="$GITHUB_REF_NAME"
notes="$(git log -1 --format=%s)"
key="$(mktemp)"
printf '%s\n' "$RELEASE_DEPLOY_KEY" > "$key"
chmod 600 "$key"
export GIT_SSH_COMMAND="ssh -i '$key' -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"
work="$(mktemp -d)"
# 分支要基于公开仓库的 main，push 触发时才找得到那边的发布工作流。
git clone -q --depth 1 git@github.com:caichengle666/sbtun.git "$work"
mkdir "$work/incoming"
cp "$@" "$work/incoming/"
printf '%s\n' "$tag" > "$work/incoming/TAG"
printf '%s\n' "$notes" > "$work/incoming/NOTES"
branch="incoming/$tag-$(basename "$1")"
cd "$work"
git add -A
git -c user.name=sbtun-ci -c user.email=ci@sbtun.invalid commit -qm "$tag"
git push -f origin "HEAD:refs/heads/$branch"
rm -f "$key"
