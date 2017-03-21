export AUFS_REPO=https://github.com/sfjro/aufs4-standalone
export AUFS_BRANCH=aufs4.4
export AUFS_COMMIT=45192fd8c7c447090b990953c62760dc18508dd7
# we use AUFS_COMMIT to get stronger repeatability guarantees

# Download AUFS and apply patches and files, then remove it
git clone -b "$AUFS_BRANCH" "$AUFS_REPO" aufs-standalone
cd aufs-standalone
git checkout -q "$AUFS_COMMIT"
cd ..
cp -r aufs-standalone/Documentation .
cp -r aufs-standalone/fs .
cp -r aufs-standalone/include/uapi/linux/aufs_type.h ./include/uapi/linux/

set -e && for patch in \
  aufs-standalone/aufs*-kbuild.patch \
  aufs-standalone/aufs*-base.patch \
  aufs-standalone/aufs*-mmap.patch \
  aufs-standalone/aufs*-standalone.patch \
  aufs-standalone/aufs*-loopback.patch \
  ; do \
  patch -p1 < "$patch"; \
done


