module app;

import credentials : SecretBuffer;

void main()
{
    auto secret = SecretBuffer(cast(const(ubyte)[]) "secret");
    string exposed = secret;
}
