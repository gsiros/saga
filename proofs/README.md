Symbolic Formal Verification of the SAGA protocol

# Reproduction Steps
1. Install the [nix package manager](https://nixos.org/download/)
2. Navigate to the current directory, and run `nix develop`. You will get dropped into a devshell with [ProVerif](https://en.wikipedia.org/wiki/ProVerif) and [Verifpal](https://verifpal.com/). Feel free to execute another shell if you don't like `bash`.
3. Run `proverif proverif/agent_communication.vp` to (automatically) prove authentication and security for Saga. The `time` module reported `proverif agent_communication.pv real 6m35.669s user 6m26.630s sys	0m4.721s` on an X1 Carbon Gen 5, i7-7600U, 16gb ddr4, running NixOS 25.11.
4. `proverif/registration.pv` implements just the SAGA agent registration protocol with a single peer. Run `proverif proverif/registration.pv` to (automatically) prove authentication for the SAGA registration protocol.

## Verifpal models
We also include `verifpal` models of the agent communication and registration protocols. One may run `verifpal verify verifpal/registration.vp` and `verifpal verify verifpal/agent_communication.vp`. However, **this will take forever** as verifpal is much slower than proverif for active attackers.
