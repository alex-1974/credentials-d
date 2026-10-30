module app;

import credentials : SecretBuffer;

void main()
{
    auto secret = new SecretBuffer(cast(const(ubyte)[]) "secret");
    string exposed = secret;
}
