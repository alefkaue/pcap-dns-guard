# Design and trust boundaries

Exercise bounded parsing of classic PCAP, Ethernet, IP, UDP and DNS question structures in offline captures.

- Supports endian-aware classic PCAP timestamps with explicit size/snaplen budgets.
- Separates incomplete capture from malformed packet metadata; fragments and unsupported protocols are skipped.
- Checks DNS label lengths, question budgets and backward compression pointers without printing query names.
- Returns structured JSON with packet numbers and file offsets; regression tests include prefix and byte-mutation smoke checks.

An educational subset, not a replacement for libpcap/Wireshark. PCAPNG, TCP DNS, IP reassembly, IPv6 extension chains and full DNS answers are unsupported. Checksums and attack attribution are not assessed.

The source snapshot is evidence supplied by the operator, not remote attestation. A metadata flag or heuristic is not proof of an attack. Tests use fixtures constructed by this repository and do not contact external targets. Do not execute or extract untrusted samples as a way to use this tool.
