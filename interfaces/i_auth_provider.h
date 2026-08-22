// interfaces/i_auth_provider.h
#pragma once

#include "../core/types/device_profile.h"
#include "../core/types/device_identity.h"
#include "../core/types/authentication_result.h"

// Authentication mechanism abstraction
// Implementations: simulation/SimulatedAuthProvider, hardware/RADIUSProvider, etc.
// Performs authentication without enrollment lookup
// Receives DeviceIdentity from VerificationWorkflow (enrollment registry)
class IAuthProvider {
public:
    virtual ~IAuthProvider() = default;

    // Authenticate a device
    // Parameters:
    //   observed - network-discovered device data
    //   enrolled - enrolled identity if found, nullptr if none
    // Returns: authentication result with success/failure and mechanism
    virtual AuthenticationResult authenticate(
        const DeviceProfile& observed,
        const DeviceIdentity* enrolled  // nullptr for unknown/unenrolled devices
    ) = 0;
};