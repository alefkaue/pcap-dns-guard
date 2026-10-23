#include "pcap_guard.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
int main(int argc, char** argv) {
    if (argc == 2 && std::string(argv[1]) == "--help") { std::cout << "pcap-dns-guard OWNED_CAPTURE.pcap [--fail-on-malformed]\nNo live capture; no names or payloads printed.\n"; return 0; }
    if (argc < 2 || argc > 3 || (argc == 3 && std::string(argv[2]) != "--fail-on-malformed")) return 2;
    try {
        const auto size = std::filesystem::file_size(argv[1]);
        if (size > 10'000'000) throw std::runtime_error("input exceeds 10 MB");
        std::ifstream stream(argv[1], std::ios::binary); if (!stream) throw std::runtime_error("cannot open input");
        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
        if (!stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) throw std::runtime_error("cannot read full input");
        const auto report = pcap_guard::inspect(bytes); std::cout << pcap_guard::json(report);
        return argc == 3 && report.malformed != 0 ? 1 : 0;
    } catch (const std::exception& error) { std::cerr << "Input error: " << error.what() << '\n'; return 2; }
}
