// core/types/packet_event.h
#pragma once

#include <string>
#include <vector>
#include <chrono>
#include "protocol.h"

// Raw packet data observed from network
// Input to PacketEvent pipeline, Phase 1 discovery, and Phase 2 detectors
// Carried by IEthernetSource::poll()
struct PacketEvent {
    std::string src_mac, dst_mac;
    std::string src_ip, dst_ip;
    uint16_t src_port = 0, dst_port = 0;
    Protocol protocol = Protocol::UNKNOWN;
    std::chrono::system_clock::time_point timestamp;
    std::vector<uint8_t> payload;    // may be empty; detectors decide if needed
};