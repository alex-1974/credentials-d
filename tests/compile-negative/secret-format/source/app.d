module app;

import credentials : SecretBuffer;
import std.format : format;

void main()
{
    auto secret = SecretBuffer(cast(const(ubyte)[]) "secret");
    auto rendered = format("%s", secret);
}
