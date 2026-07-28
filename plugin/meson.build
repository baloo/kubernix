project('kubernix-plugin', 'cpp',
  version : '0.1.0',
  default_options : [
    'cpp_std=c++23',
    'optimization=2',
  ]
)

add_project_arguments(
  language : 'cpp',
)

cpp_compiler = meson.get_compiler('cpp')

if cpp_compiler.get_id() != 'clang'
  error('This project requires Clang. Please run: CXX=clang++ meson setup builddir')
endif

# Fetch Lix and curl dependencies using pkg-config
lix_main = dependency('lix-main')
lix_store = dependency('lix-store')
lix_expr = dependency('lix-expr')
libcurl = dependency('libcurl')

nlohmann_json = dependency('nlohmann_json')
capnp_dep = dependency('capnp')

capnp = find_program('capnp', required: true)
capnpc_cpp = find_program('capnpc-c++', required: true)

capnp_gen = generator(
  capnp,
  output: ['@BASENAME@.capnp.c++', '@BASENAME@.capnp.h'],
  arguments: ['compile', '-o', 'c++:@BUILD_DIR@', '--src-prefix=' + meson.project_source_root() + '/../protocol', '@INPUT@']
)
protocol_src = capnp_gen.process('../protocol/kubernix.capnp')

# Create the shared module (plugin) without a 'lib' prefix
shared_module('kubernix',
  'src/plugin.cc', protocol_src,
  dependencies : [lix_main, lix_store, lix_expr, libcurl, nlohmann_json, capnp_dep],
  install : true,
  install_dir : get_option('libdir') / 'lix' / 'plugins',
  name_prefix : '',
)

configdata = configuration_data()
host_cpu = host_machine.cpu_family()
if host_cpu in ['x86', 'i686', 'i386']
  # Meson considers 32-bit x86 CPUs to be "x86", and does not consider 64-bit
  # x86 CPUs to be "x86" (instead using "x86_64", which needs no translation).
  host_cpu = 'i686'
elif host_cpu == 'amd64'
  # This should not be needed under normal circumstances, but someone could pass a --cross-file
  # that sets the cpu_family to this.
  host_cpu = 'x86_64'
elif host_cpu in ['armv6', 'armv7']
  host_cpu += 'l'
elif host_cpu == 'arm'
  # Too generic, we use more specific ones
  host_cpu = host_machine.cpu()
elif host_cpu in ['mips', 'mips64']
  # LE is suffixed with 'el'
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
configdata.set_quoted('SYSTEM', host_system)
configdata.set('HAVE_STRUCT_DIRENT_D_TYPE', 1)
configdata.set('LIX_UR_COMPILER_UWU', 1)

config_h = configure_file(
  configuration : configdata,
  output : 'config.h',
)

install_headers(config_h, subdir : 'kubernix')
