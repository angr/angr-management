#!/bin/bash
set -e #-x
cd "$(dirname "$0")"
cd ..

sync_vendor_tree() {  # (name, src_repo, src_branch, src_subdir, src_license)
	echo "[*] Syncing $1"
	remote=vendor-$1 src_repo=$2 src_branch=$3 src_dir=$4 dst_dir=angrmanagement/vendor/$1 src_license=$5
	if [[ -d $dst_dir ]]; then git rm -rf $dst_dir; fi
	git remote add -f -t $src_branch --no-tags $remote $src_repo 2>/dev/null || git fetch $remote --no-tags
	git read-tree --prefix=$dst_dir -u $remote/$src_branch:$src_dir
	dst_license=$dst_dir/LICENSE
	git show $remote/$src_branch:$src_license >$dst_license && git add $dst_license
	git commit -m "$dst_dir: Update to $(git rev-parse $remote/$src_branch)"
}

sync_vendor_tree qtconsole https://github.com/angr/qtconsole angr-management qtconsole LICENSE
