with import ./nix/nixpkgs.nix {};

let
  vi = neovim.override {
    configure = {
      customRC = ''
        set mouse=
	let g:rustfmt_autosave = 1
      '';

      packages.rust = with vimPlugins; {
        start = [ rust-vim ];
	opt = [ ];
      };
    };
  };
in
mkShell {
  nativeBuildInputs = [
    just

    cargo rustc rustfmt clippy

    cargo-watch cargo-expand
    rust-analyzer

    rustfs
    nats-server

    capnproto
    meson
    ninja
    pkg-config
    clang
    gdb

    lix

    kubernetes-helm skopeo
  ];

  buildInputs = [
    boost
    boehmgc.dev
    nlohmann_json

    vi
  ];

  shellHook = ''
    alias vi="${vi}/bin/nvim";
    alias vim=vi;
  '';

  EDITOR="vi";
  CXX="clang";
}
