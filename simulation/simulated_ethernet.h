// simulation/simulated_ethernet.h
#pragma once

#include <vector>
#include "../interfaces/i_ethernet_source.h"
#include "../core/types/packet_event.h"

// IEthernetSource implementation (simulator)
// Replays a fixed sequence of PacketEvents deterministically - the same input
// every run, which is what makes end-to-end tests reliable.
// A scenario is an explicit list of packets owned by the caller (or built by
// a helper) and passed in at construction.
class SimulatedEthernet : public IEthernetSource {
public:
    explicit SimulatedEthernet(std::vector<PacketEvent> scenario);

    std::optional<PacketEvent> poll() override;
    void start() override;
    void stop() override;

    // Remaining packets not yet polled (useful for tests/diagnostics)
    size_t remaining() const;

private:
    std::vector<PacketEvent> scenario_;
    size_t index_ = 0;
    bool running_ = false;
};