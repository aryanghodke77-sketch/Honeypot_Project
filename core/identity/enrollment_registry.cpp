// core/identity/enrollment_registry.cpp
#include "enrollment_registry.h"

bool EnrollmentRegistry::enroll(const DeviceIdentity& identity) {
    auto [it, inserted] = by_mac_.emplace(identity.mac, identity);
    return inserted;
}

const DeviceIdentity* EnrollmentRegistry::lookup(const std::string& mac) const {
    auto it = by_mac_.find(mac);
    return it == by_mac_.end() ? nullptr : &it->second;
}

bool EnrollmentRegistry::revoke(const std::string& device_id) {
    for (auto it = by_mac_.begin(); it != by_mac_.end(); ++it) {
        if (it->second.device_id == device_id) {
            by_mac_.erase(it);
            return true;
        }
    }
    return false;
}

size_t EnrollmentRegistry::size() const {
    return by_mac_.size();
}