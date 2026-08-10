project('kubernix-plugin', 'cpp',
  version : '0.1.0',
  default_options : [
    'cpp_std=c++23',
    'optimization=2',
  ]
)

cpp_compiler = meson.get_compiler('cpp')

if cpp_compiler.get_id() != 'clang'
  error('This project requires Clang. Please run: CXX=clang++ meson setup builddir')
endif

lix_main = dependency('lix-main')
lix_store = dependency('lix-store')
lix_util = dependency('lix-util')
capnp_dep = dependency('capnp')
capnp_rpc_dep = dependency('capnp-rpc')

capnp = find_program('capnp', required : true)

# Lix does not install the generated capnp headers for libstore, even though it
# installs daemon-rpc.hh which includes them, and even though libutil installs
# its own. We regenerate them here from Lix's schema sources; the output is
# byte-identical to Lix's build tree. See NOTES.md item 1.
#
# Generated from the *Lix source we link against* rather than a vendored copy on
# purpose: we rely on liblix-store.so to supply the schema blobs, so the headers
# must describe exactly the schema that library was built with.
lix_source = get_option('lix-source')
if lix_source == ''
  error(
    'lix-source is unset. Point it at the Lix source tree matching the Lix ' +
    'being linked, e.g. -Dlix-source=/path/to/lix (Nix passes ${lix.src}).'
  )
endif

lixgen = meson.current_build_dir() / 'lixgen'
run_command('mkdir', '-p', lixgen, check : true)
run_command(
  capnp, 'compile',
  '-oc++:' + lixgen,
  '--src-prefix=' + lix_source,
  '-I' + lix_source,
  lix_source / 'lix/libstore/daemon.capnp',
  lix_source / 'lix/libstore/types.capnp',
  check : true,
)

# Only the headers are used. The corresponding .c++ schema blobs are deliberately
# NOT compiled in: liblix-store.so already exports them, verified by linking a
# probe both with and without. See NOTES.md item 1.

lix_includedir = lix_store.get_variable(pkgconfig : 'includedir')

kubernix_cpp_args = [
  # daemon-rpc.hh includes "libstore/build-result.hh" without the lix/ prefix,
  # so the include root itself must be on the path. See NOTES.md item 2.
  '-I' + lix_includedir / 'lix',
  '-I' + lixgen,
]

shared_module('kubernix',
  'src/plugin.cc',
  dependencies : [lix_main, lix_store, lix_util, capnp_dep, capnp_rpc_dep],
  cpp_args : kubernix_cpp_args,
  install : true,
  install_dir : get_option('libdir') / 'lix' / 'plugins',
  name_prefix : '',
)

configdata = configuration_data()
host_cpu = host_machine.cpu_family()
if host_cpu in ['x86', 'i686', 'i386']
  host_cpu = 'i686'
elif host_cpu == 'amd64'
  host_cpu = 'x86_64'
elif host_cpu in ['armv6', 'armv7']
  host_cpu += 'l'
elif host_cpu == 'arm'
  host_cpu = host_machine.cpu()
elif host_cpu in ['mips', 'mips64']
  if host_machine.endian() == 'little'
    host_cpu += 'el'
  endif
elif host_cpu == 'ppc'
  host_cpu = 'powerpc'
  if host_machine.endian() == 'little'
    host_cpu += 'le'
  endif
elif host_cpu == 'ppc64'
  host_cpu = 'powerpc64'
  if host_machine.endian() == 'little'
    host_cpu += 'le'
  endif
endif
host_system = host_cpu + '-' + host_machine.system()
# SYSTEM is required by libstore-settings.gen.inc, pulled in transitively.
configdata.set_quoted('SYSTEM', host_system)
configdata.set('HAVE_STRUCT_DIRENT_D_TYPE', 1)
configdata.set('LIX_UR_COMPILER_UWU', 1)

config_h = configure_file(
  configuration : configdata,
  output : 'config.h',
)

install_headers(config_h, subdir : 'kubernix')
