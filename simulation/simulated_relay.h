// simulation/simulated_relay.h
#pragma once

#include <string>
#include "../interfaces/i_relay.h"
#include "../interfaces/i_logger.h"

// IRelay implementation (simulator)
// Logs allow/block actions via an ILogger; later replaced by real switch /
// traffic controller hardware behind the same interface.
class SimulatedRelay : public IRelay {
public:
    explicit SimulatedRelay(ILogger& logger);

    void allow(const std::string& device_id) override;
    void block(const std::string& device_id) override;

private:
    ILogger& logger_;
};