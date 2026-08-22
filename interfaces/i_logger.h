// interfaces/i_logger.h
#pragma once

#include <string>

// Logging level enumeration
enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR
};

// Logging abstraction for hardware independence
// Implementations: simulation/ConsoleLogger, hardware/ESP32FlashLogger
class ILogger {
public:
    virtual ~ILogger() = default;
    virtual void log(LogLevel level, const std::string& msg) = 0;
};