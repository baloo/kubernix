{ buildMember }:

buildMember {
  name = "kubernix-worker";
  path = ../crates/worker;
  additionalCrates = [
    ../crates/daemon-protocol
    ../crates/guest-protocol
  ];
}
