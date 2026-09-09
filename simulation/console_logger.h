// simulation/console_logger.h
#pragma once

#include "../interfaces/i_logger.h"

// ILogger implementation that prints to stdout (simulator)
// Later replaced by a structured logger on the ESP32 (flash/SD card)
class ConsoleLogger : public ILogger {
public:
    void log(LogLevel level, const std::string& msg) override;
};