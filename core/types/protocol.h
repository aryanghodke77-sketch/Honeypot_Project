// core/types/protocol.h
#pragma once

// Packet protocol enumeration
// Used by PacketEvent to identify packet type
enum class Protocol {
    TCP,
    UDP,
    ARP,
    DHCP,
    ICMP,
    UNKNOWN
};