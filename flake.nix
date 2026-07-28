{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "github:baloo/nixpkgs?ref=push-vzsuuotmlxur";
    lix.url = "git+https://git.lix.systems/lix-project/lix.git";
  };

  outputs = inputs: {
  };
}
