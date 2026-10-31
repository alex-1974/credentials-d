module app;

import credentials : CredentialStatus;
import credentials.backend.fido2 :
    Fido2Capabilities,
    Fido2DeviceInfo,
    discoverFido2Devices,
    queryFido2Capabilities;

void main()
{
    Fido2DeviceInfo[] devices;

    const status = discoverFido2Devices(devices);
    assert(status == CredentialStatus.ok);

    foreach (const device; devices)
        assert(device.path.length != 0);

    Fido2Capabilities capabilities;
    assert(
        queryFido2Capabilities("", capabilities) ==
        CredentialStatus.invalidInput
    );
    assert(capabilities.remainingDiscoverableCredentials == -1);
}
