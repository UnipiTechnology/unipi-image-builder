# Unipi Image Builder

Simple, configurable tool to build Debian images. The tool is basically frontend to [mmdebstrap - multi-mirror Debian chroot creator](https://gitlab.mister-muffin.de/josch/mmdebstrap)

Frontend is based on Kconfig language and Makefiles and is used it like building Linux kernel

``` 
    make patron-nodered_defconfig
    make menuconfig
    make format
    make
```

## Requirements
- mmdebstrap
- apt
- make
- fakeroot
- kconfig-frontends-nox
- python3-jinja2
- j2
- pigz, zip
- mtools
- qemu-system-arm
- trivy (only when SBOM generation with the Trivy backend is enabled in `make menuconfig`)
- debsbom + python3-cyclonedx-lib (only when SBOM generation with the debsbom backend is enabled in `make menuconfig`)
  - debsbom currently supports CycloneDX out-of-the-box on Debian trixie.
    SPDX JSON requires `python3-spdx-tools`, which is **not packaged in
    trixie** (only in sid) — install it via pip or a venv if you need
    SPDX, otherwise stick to CycloneDX.

On Debian system use this commands

```
  sudo apt install mmdebstrap make fakechroot kconfig-frontends-nox qemu-system-arm binfmt-support
  sudo apt install python3-yaml j2cli e2fsprogs pigz dosfstools cpio zip fdisk mtools
  sudo update-binfmts --enable qemu-aarch64

```


## Makefile options

- mmopt-y          - list of hooks to run
- mmpre-y          - list of hooks to run before mmopt-y hooks
- mmpost-y         - list of hooks to run after mmopt-y hooks
- sources-y        - list of directories with apt source definition
- pkgs-y           - list of packages to install
- local-pkgs-y     - list of local file packages to install
- local-uploads-y
- components-y     - list of apt components to install (main, test ...)

## Customizing

To customize the image build, call ```make menuconfig``` where you can choose from predefined options.
The output format is selected by calling ```make format```. Make always creates tar file that contains all installed files.
The desired images are than generated from it. All temporary files and images are placed into build directory.

If you are not satisfied with options offered, you can create own addon to extend the installation options.

# Create your addon

Create own directory in directory addons
 ```mkdir addons/myapp```

Create in that directory Kconfig and Makefile

addons/myapp/Kconfig
```
config MYAPP
        bool "Install and customize MyApp"
        default n
```

addons/myapp/Makefile
```
pkgs-$(CONFIG_MYAPP) += myapp,nginx
mmopt-$(CONFIG_MYAPP) += --customize-hook='upload addons/myapp/my.cfg /etc/my.cfg'
mmopt-$(CONFIG_MYAPP) += --hook-dir=addons/myapp/hook
```
