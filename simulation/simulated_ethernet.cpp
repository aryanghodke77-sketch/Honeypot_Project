// simulation/simulated_ethernet.cpp
#include "simulated_ethernet.h"

SimulatedEthernet::SimulatedEthernet(std::vector<PacketEvent> scenario)
    : scenario_(std::move(scenario)) {}

std::optional<PacketEvent> SimulatedEthernet::poll() {
    if (!running_ || index_ >= scenario_.size()) {
        return std::nullopt;
    }
    return scenario_[index_++];
}

void SimulatedEthernet::start() { running_ = true; }
void SimulatedEthernet::stop() { running_ = false; }

size_t SimulatedEthernet::remaining() const {
    return scenario_.size() - index_;
}