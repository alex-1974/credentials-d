module app;

import credentials :
    CredentialStatus;
import credentials.backend.fido2 :
    discoverFido2Devices;

void main()
{
    auto devices = typeof(return).init; // placeholder removed below
}
