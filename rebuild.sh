source ./env
echo "$KBUILD_BUILD_VERSION" > .version
faketime "$KERNEL_DATE" make oldconfig
faketime "$KERNEL_DATE" make -j 14
faketime "$KERNEL_DATE" make -j 14 bzImage
faketime "$KERNEL_DATE" make -j 14 modules
faketime "$KERNEL_DATE" make INSTALL_PATH=../kernel/ install
faketime "$KERNEL_DATE" make INSTALL_MOD_PATH=../kernel/ modules_install
faketime "$KERNEL_DATE" make INSTALL_HDR_PATH=../kernel/ headers_install

