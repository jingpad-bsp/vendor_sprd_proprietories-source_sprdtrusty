cc_library_shared {
    name: "libsoter_checkx",

    srcs: ["soter_checkx.c"],

    relative_install_path: "npidevice",
    proprietary: true,

    include_dirs: ["vendor/sprd/proprietories-source/engpc/sprd_fts_inc"],

    shared_libs: [
        "liblog",
        "libc",
        "libcutils",
        "libteeproduction",
    ],

}
