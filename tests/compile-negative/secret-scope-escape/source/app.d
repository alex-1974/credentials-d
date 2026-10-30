module app;

import credentials : SecretBuffer;

const(ubyte)[] escaped;

void main()
{
    auto secret = new SecretBuffer(cast(const(ubyte)[]) "secret");

    secret.withBytes((scope const(ubyte)[] bytes) @safe
    {
        escaped = bytes;
    });
}
