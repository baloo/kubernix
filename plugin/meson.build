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

# Three workarounds used to live here, all for Lix packaging bugs that have since
# been fixed upstream (NOTES.md items 1-3):
#
#   * generated capnp headers were not installed  -> lix b8f75f742
#   * daemon-rpc.hh used build-tree-relative includes -> lix ee252770f
#   * daemon-rpc.hh was not self-contained        -> lix 7104538c1
#
# Nothing replaces them: the installed headers are now sufficient on their own.
# That is also why `-Dlix-source` is gone — it existed only to regenerate the
# headers, so the plugin no longer needs a Lix *source* tree at all, just the
# package.
#
# The schema blobs are still deliberately NOT compiled in: liblix-store.so
# exports them, verified by linking a probe both with and without.

shared_module('kubernix',
  'src/plugin.cc',
  dependencies : [lix_main, lix_store, lix_util, capnp_dep, capnp_rpc_dep],
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
