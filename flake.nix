{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    lix.url = "github:lix-project/lix";
  };

  outputs = inputs: {
  };
}
