source ./env
echo "$KBUILD_BUILD_VERSION" > .version
faketime "$KERNEL_DATE" make INSTALL_PATH=$BOOT2DOCKER_SRC/kernel install
faketime "$KERNEL_DATE" make INSTALL_MOD_PATH=$BOOT2DOCKER_SRC/kernel modules_install
faketime "$KERNEL_DATE" make INSTALL_HDR_PATH=$BOOT2DOCKER_SRC/kernel headers_install

