// simulation/console_logger.cpp
#include "console_logger.h"
#include <iostream>

void ConsoleLogger::log(LogLevel level, const std::string& msg) {
    const char* prefix = "INFO ";
    switch (level) {
        case LogLevel::DEBUG:   prefix = "DEBUG"; break;
        case LogLevel::INFO:    prefix = "INFO "; break;
        case LogLevel::WARNING: prefix = "WARN "; break;
        case LogLevel::ERROR:   prefix = "ERROR"; break;
    }
    std::cout << "[" << prefix << "] " << msg << "\n";
}