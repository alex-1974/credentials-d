module app;

import credentials : CredentialStatus;
import credentials.backend.fido2 :
    Fido2DeviceInfo,
    discoverFido2Devices;

void main()
{
    Fido2DeviceInfo[] devices;

    const status = discoverFido2Devices(devices);
    assert(status == CredentialStatus.ok);

    foreach (const device; devices)
        assert(device.path.length != 0);
}
