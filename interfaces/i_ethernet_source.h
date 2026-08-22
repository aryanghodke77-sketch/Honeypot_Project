// interfaces/i_ethernet_source.h
#pragma once

#include <optional>
#include "../core/types/packet_event.h"

// Ethernet packet input abstraction
// Implementations: simulation/SimulatedEthernet, hardware/ESP32EthernetSource
// Provides non-blocking packet polling for hardware independence
class IEthernetSource {
public:
    virtual ~IEthernetSource() = default;

    // Poll for next packet (non-blocking)
    // Returns nullopt if no packet available
    virtual std::optional<PacketEvent> poll() = 0;

    // Start packet capture
    virtual void start() = 0;

    // Stop packet capture
    virtual void stop() = 0;
};