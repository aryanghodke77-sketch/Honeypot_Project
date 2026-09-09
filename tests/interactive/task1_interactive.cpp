// tests/interactive/task1_interactive.cpp
#include <iostream>
#include <string>
#include <chrono>
#include "../../core/types/packet_event.h"
#include "../../core/types/device_identity.h"
#include "../../core/types/trust_decision.h"

using namespace std;
using namespace std::chrono;

int main() {
    cout << "=== Security Jack: Task 1 Interactive Verifier ===\n\n";
    cout << "This tool lets you interactively construct core data models\n";
    cout << "to verify that the structures compile and behave as expected.\n\n";

    cout << "--- 1. Create a Packet Event ---\n";
    PacketEvent pkt;
    cout << "Enter Source MAC (e.g., 00:11:22:33:44:55): ";
    getline(cin, pkt.src_mac);
    cout << "Enter Dest MAC: ";
    getline(cin, pkt.dst_mac);
    
    pkt.protocol = Protocol::TCP;
    pkt.timestamp = system_clock::now();
    
    cout << "\n[Success] Created PacketEvent from " << pkt.src_mac << " to " << pkt.dst_mac << "\n\n";

    cout << "--- 2. Create a Trust Decision ---\n";
    TrustDecision decision;
    cout << "Enter Trust Reason for this device: ";
    getline(cin, decision.reason);
    decision.level = TrustLevel::TRUSTED;
    decision.decided_at = system_clock::now();

    cout << "\n[Success] Created Decision: TRUSTED based on reason: '" << decision.reason << "'\n\n";
    
    cout << "Verification Successful: Data models are instantiable and editable!\n";
    cout << "Press Enter to exit.";
    cin.get();
    
    return 0;
}
