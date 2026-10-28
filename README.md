# PCAP DNS Guard

**Portfolio area:** [Cybersecurity](https://github.com/alefkaue#cybersecurity) · **Context:** Personal project

**C++ · offline defensive analysis · original personal portfolio project**

Exercise bounded parsing of classic PCAP, Ethernet, IP, UDP and DNS question structures in offline captures.

[Português](README.pt-BR.md) · [Design and limits](docs/design.md) · [Executed example output](docs/demo-output.txt)

## Run and test

C++20 compiler and CMake 3.20+. No external C++ libraries. Binaries are under build/ on single-config generators and build/Release/ with Visual Studio. Add that directory to PATH or invoke the executable explicitly.

```console
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
python examples/make_demo.py
pcap-dns-guard examples/synthetic.pcap
```

## Features

- Supports endian-aware classic PCAP timestamps with explicit size/snaplen budgets.
- Separates incomplete capture from malformed packet metadata; fragments and unsupported protocols are skipped.
- Checks DNS label lengths, question budgets and backward compression pointers without printing query names.
- Returns structured JSON with packet numbers and file offsets; regression tests include prefix and byte-mutation smoke checks.

## Evidence and limits

An educational subset, not a replacement for libpcap/Wireshark. PCAPNG, TCP DNS, IP reassembly, IPv6 extension chains and full DNS answers are unsupported. Checksums and attack attribution are not assessed.

The committed examples/output files come from synthetic local runs. They are not customer results,
professional assessments or demonstrations against third-party systems. Input paths and archive names
can still be sensitive: keep real reports private. No account, service or network configuration is changed.

## Engineering

Parsing, decisions and output are separate from CLI argument handling. Tests cover positive cases,
ambiguous evidence and malformed data. GitHub Actions builds/tests on Windows and Linux with
read-only repository permissions and actions pinned by commit. See docs/tests.txt for the recorded local run.

Built by Alef Kaue Santos Nunes with AI assistance. This does not claim professional experience or
independent vulnerability discovery. MIT covers original code and documentation.

## Reference

- [Official format/API reference](https://man7.org/linux/man-pages/man5/pcap-savefile.5.html)
