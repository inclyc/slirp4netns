project(
     'slirp4netns' ,
     [ 'c', 'cpp' ],
     default_options : [
        'warning_level=3',
        'cpp_std=gnu++23',
        'cpp_eh=none'
     ]
)

glib = dependency('glib-2.0')
libcap = dependency('libcap')
libslirp = dependency('slirp', version: '>= 4.1.0')

cpp = meson.get_compiler('cpp')

version = meson.project_version()

conf = configuration_data()
# Surround the version in quotes to make it a C string
conf.set_quoted('VERSION', version)
conf.set_quoted('PACKAGE_VERSION', version)

configure_file(
    output : 'config.h',
    configuration : conf
)

add_project_arguments([
  cpp.get_supported_arguments(
     '-Werror=unused-parameter',
     '-Werror=macro-redefined',
  ),
], language: 'cpp')


executable(
    'slirp4netns',
    'cleanup.cpp',
    'child.cpp',
    'slirp4netns.cpp',
    'main.cpp',
    'sockfd.cpp',
    'syscall.cpp',
    dependencies: [ glib, libcap, libslirp ],
)
