#include "pcap_guard.hpp"
#include <array>
#include <sstream>
#include <stdexcept>

namespace pcap_guard {
namespace {
using Bytes = std::span<const std::uint8_t>;
std::uint16_t u16(Bytes b, std::size_t p, bool little = false) {
    if (p > b.size() || b.size() - p < 2) throw std::runtime_error("truncated 16-bit field");
    return little ? static_cast<std::uint16_t>(b[p] | (b[p + 1] << 8))
                  : static_cast<std::uint16_t>((b[p] << 8) | b[p + 1]);
}
std::uint32_t u32(Bytes b, std::size_t p, bool little) {
    if (p > b.size() || b.size() - p < 4) throw std::runtime_error("truncated 32-bit field");
    std::uint32_t n = 0;
    for (std::size_t i = 0; i < 4; ++i) n |= static_cast<std::uint32_t>(b[p + i]) << (8 * (little ? i : 3 - i));
    return n;
}
std::size_t name_size(Bytes dns, std::size_t start) {
    std::size_t p = start, consumed = 0, expanded = 0, jumps = 0;
    bool jumped = false;
    while (true) {
        if (p >= dns.size()) throw std::runtime_error("truncated DNS name");
        const auto length = dns[p];
        if ((length & 0xc0) == 0xc0) {
            const auto target = static_cast<std::size_t>(u16(dns, p) & 0x3fff);
            if (target >= p || ++jumps > 32) throw std::runtime_error("invalid DNS compression pointer");
            if (!jumped) consumed += 2;
            jumped = true; p = target; continue;
        }
        if ((length & 0xc0) != 0) throw std::runtime_error("reserved DNS label encoding");
        ++p; if (!jumped) ++consumed;
        if (length == 0) return consumed;
        if (dns.size() - p < length) throw std::runtime_error("truncated DNS label");
        expanded += length + 1;
        if (expanded > 254) throw std::runtime_error("expanded DNS name too long");
        p += length; if (!jumped) consumed += length;
    }
}
std::size_t dns_questions(Bytes dns) {
    if (dns.size() < 12) throw std::runtime_error("truncated DNS header");
    if ((u16(dns, 2) & 0x8000) != 0) return 0; // responses are outside the question counter
    const auto count = u16(dns, 4);
    if (count > 32) throw std::runtime_error("DNS question count exceeds parser budget");
    std::size_t p = 12;
    for (std::uint16_t i = 0; i < count; ++i) {
        p += name_size(dns, p);
        if (p > dns.size() || dns.size() - p < 4) throw std::runtime_error("truncated DNS question fields");
        p += 4;
    }
    return count;
}
std::size_t packet_dns(Bytes frame, bool& skipped, bool& truncated) {
    if (frame.size() < 14) throw std::runtime_error("truncated Ethernet header");
    std::size_t ip = 14; auto ether_type = u16(frame, 12);
    if (ether_type == 0x8100) {
        if (frame.size() < 18) throw std::runtime_error("truncated VLAN header");
        ether_type = u16(frame, 16); ip = 18;
    }
    std::size_t udp = 0, end = 0;
    if (ether_type == 0x0800) {
        if (frame.size() - ip < 20 || frame[ip] >> 4 != 4) throw std::runtime_error("invalid IPv4 header");
        const std::size_t header = (frame[ip] & 15) * 4;
        const auto total = static_cast<std::size_t>(u16(frame, ip + 2));
        if (header < 20 || total < header || frame.size() - ip < header) throw std::runtime_error("invalid IPv4 lengths");
        if ((u16(frame, ip + 6) & 0x3fff) != 0) { skipped = true; return 0; }
        if (frame.size() - ip < total) { truncated = true; return 0; }
        if (frame[ip + 9] != 17) { skipped = true; return 0; }
        udp = ip + header; end = ip + total;
    } else if (ether_type == 0x86dd) {
        if (frame.size() - ip < 40 || frame[ip] >> 4 != 6) throw std::runtime_error("invalid IPv6 header");
        if (frame[ip + 6] != 17) { skipped = true; return 0; } // extension chains not guessed
        const auto payload = static_cast<std::size_t>(u16(frame, ip + 4));
        if (frame.size() - ip - 40 < payload) { truncated = true; return 0; }
        udp = ip + 40; end = udp + payload;
    } else { skipped = true; return 0; }
    if (end - udp < 8) throw std::runtime_error("truncated UDP header");
    const auto length = static_cast<std::size_t>(u16(frame, udp + 4));
    if (length < 8 || length > end - udp) throw std::runtime_error("invalid UDP length");
    if (u16(frame, udp) != 53 && u16(frame, udp + 2) != 53) { skipped = true; return 0; }
    return dns_questions(frame.subspan(udp + 8, length - 8));
}
}
Report inspect(std::span<const std::uint8_t> bytes) {
    if (bytes.size() > 10'000'000) throw std::runtime_error("input exceeds 10 MB");
    if (bytes.size() < 24) throw std::runtime_error("truncated PCAP global header");
    const auto magic = u32(bytes, 0, false);
    const bool little = magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1;
    const bool nano = magic == 0xa1b23c4d || magic == 0x4d3cb2a1;
    if (!little && magic != 0xa1b2c3d4 && magic != 0xa1b23c4d) throw std::runtime_error("unsupported format; classic PCAP required, not PCAPNG");
    if (u16(bytes, 4, little) != 2 || u16(bytes, 6, little) != 4) throw std::runtime_error("unsupported PCAP version");
    const auto snaplen = u32(bytes, 16, little);
    if (snaplen == 0 || snaplen > 1'048'576) throw std::runtime_error("invalid or excessive snaplen");
    if (u32(bytes, 20, little) != 1) throw std::runtime_error("only plain Ethernet link type is supported");
    Report result; std::size_t p = 24;
    while (p < bytes.size()) {
        if (bytes.size() - p < 16) throw std::runtime_error("truncated PCAP packet header");
        const auto fraction = u32(bytes, p + 4, little);
        const auto captured = u32(bytes, p + 8, little), original = u32(bytes, p + 12, little);
        if (fraction >= (nano ? 1'000'000'000u : 1'000'000u)) throw std::runtime_error("invalid PCAP timestamp fraction");
        if (captured > snaplen || captured > original || captured > bytes.size() - p - 16) throw std::runtime_error("invalid or truncated PCAP record length");
        ++result.packets; bool skipped = false, truncated = false;
        try { result.dns_questions += packet_dns(bytes.subspan(p + 16, captured), skipped, truncated); }
        catch (const std::runtime_error& error) { ++result.malformed; result.observations.push_back({result.packets, p + 16, error.what()}); }
        if (skipped) ++result.skipped;
        if (truncated || captured < original) { ++result.truncated; result.observations.push_back({result.packets, p + 16, "capture incomplete; do not infer malformed original traffic"}); }
        p += 16 + captured;
    }
    return result;
}
std::string json(const Report& r) {
    std::ostringstream out;
    out << "{\"scope\":\"Offline classic-PCAP validation; no capture, traffic generation or attack attribution\",\"packets\":" << r.packets
        << ",\"dns_questions\":" << r.dns_questions << ",\"malformed_packets\":" << r.malformed << ",\"skipped_packets\":" << r.skipped
        << ",\"capture_incomplete\":" << r.truncated << ",\"observations\":[";
    for (std::size_t i = 0; i < r.observations.size(); ++i) {
        if (i) out << ',';
        const auto& o = r.observations[i];
        out << "{\"packet\":" << o.packet << ",\"offset\":" << o.offset << ",\"reason\":\"" << o.reason << "\"}";
    }
    return out.str() + "]}\n";
}
}
