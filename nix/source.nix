{ lib, runCommand }:

# Source trees for the Rust crates.
#
# The old `gitignoreRecursiveSource [] ../.` had to walk the whole repository
# root, `target/` included (tens of gigabytes), before deciding what to drop.
# Here we name the directories we want instead, so nothing else is ever read.
#
# The crates cannot simply be copied on their own though: `server/build.rs` and
# `worker/build.rs` reach for `../protocol`, so the checked-out tree has to
# reproduce the repository topology. `workspace` reassembles exactly that.

let
  # A plain directory, copied verbatim into its own store path.
  dir = path: lib.fileset.toSource {
    root = path;
    fileset = path;
  };
in rec {
  # The Cap'n Proto schemas, in a store path of their own so that every crate
  # referring to them shares the same derivation.
  protocol = dir ../protocol;

  # `crates` are top-level directory names, relative to the repository root.
  # Workspace members must all be present, even the ones a given package does
  # not build: dropping a member would change the set of packages Cargo sees
  # and make it reject the (unchanged) lock file.
  workspace = { name, crates }: runCommand name { } ''
    mkdir -p $out
    cp ${../Cargo.toml} $out/Cargo.toml
    cp ${../Cargo.lock} $out/Cargo.lock
    cp -r ${protocol} $out/protocol
    ${lib.concatMapStringsSep "\n"
      (crate: "cp -r ${dir (../. + "/${crate}")} $out/${crate}")
      crates}
    chmod -R u+w $out
  '';
}
