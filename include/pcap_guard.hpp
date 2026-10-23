#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace pcap_guard {
struct Observation { std::size_t packet; std::size_t offset; std::string reason; };
struct Report {
    std::size_t packets{}, dns_questions{}, malformed{}, skipped{}, truncated{};
    std::vector<Observation> observations;
};
Report inspect(std::span<const std::uint8_t> bytes);
std::string json(const Report& report);
}
