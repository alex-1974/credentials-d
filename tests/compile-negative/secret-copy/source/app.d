module app;

import credentials : SecretBuffer;

void main()
{
    auto secret = SecretBuffer(cast(const(ubyte)[]) "secret");
    auto copied = secret;
}
