// simulation/simulated_relay.cpp
#include "simulated_relay.h"

SimulatedRelay::SimulatedRelay(ILogger& logger) : logger_(logger) {}

void SimulatedRelay::allow(const std::string& device_id) {
    logger_.log(LogLevel::INFO, "RELAY: allow access for " + device_id);
}

void SimulatedRelay::block(const std::string& device_id) {
    logger_.log(LogLevel::ERROR, "RELAY: block access for " + device_id);
}