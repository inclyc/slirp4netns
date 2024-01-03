project(
     'slirp4netns' ,
     [ 'c', 'cpp' ]
)

glib = dependency('glib-2.0')
libcap = dependency('libcap')
libseccomp = dependency('libseccomp')
libslirp = dependency('slirp', version: '>= 4.1.0')

cpp = meson.get_compiler('cpp')

parson = library(
    'parson',
    'vendor/parson/parson.c',
    include_directories: [ 'vendor/parson' ]
)


version = meson.project_version()

conf = configuration_data()
# Surround the version in quotes to make it a C string
conf.set_quoted('VERSION', version)
conf.set_quoted('PACKAGE_VERSION', version)

configure_file(
    output : 'config.h',
    configuration : conf
)

executable(
    'slirp4netns',
    'api.c',
    'slirp4netns.c',
    'main.c',
    dependencies: [ glib, libcap, libseccomp, libslirp ],
    link_with: [ parson ]
)
