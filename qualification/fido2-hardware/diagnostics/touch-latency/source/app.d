module app;

version (linux):

import core.stdc.stdlib : free, malloc;
import core.sys.posix.termios : ECHO, TCSANOW, tcgetattr, tcsetattr, termios;
import core.sys.posix.unistd : STDIN_FILENO, isatty;
import core.time : MonoTime;
import core.volatile : volatileStore;
import std.stdio : stdin, stderr, stdout;
import std.string : fromStringz, toStringz;

struct FidoDev;
struct FidoCred;
struct FidoAssert;
struct FidoDevInfo;

alias fido_dev_t = FidoDev;
alias fido_cred_t = FidoCred;
alias fido_assert_t = FidoAssert;
alias fido_dev_info_t = FidoDevInfo;

enum int FIDO_OK = 0;
enum int FIDO_DISABLE_U2F_FALLBACK = 0x02;
enum int FIDO_EXT_HMAC_SECRET = 0x01;
enum int COSE_ES256 = -7;

enum FidoOpt : int
{
    omit = 0,
    false_ = 1,
    true_ = 2
}

extern(C) @nogc nothrow
{
    void fido_init(int flags);
    const(char)* fido_strerr(int status);

    fido_dev_info_t* fido_dev_info_new(size_t n);
    void fido_dev_info_free(fido_dev_info_t** list, size_t n);
    int fido_dev_info_manifest(fido_dev_info_t* list, size_t capacity, size_t* count);
    const(fido_dev_info_t)* fido_dev_info_ptr(const(fido_dev_info_t)* list, size_t index);
    const(char)* fido_dev_info_path(const(fido_dev_info_t)* info);
    const(char)* fido_dev_info_manufacturer_string(const(fido_dev_info_t)* info);
    const(char)* fido_dev_info_product_string(const(fido_dev_info_t)* info);

    fido_dev_t* fido_dev_new();
    void fido_dev_free(fido_dev_t** dev);
    int fido_dev_open(fido_dev_t* dev, const(char)* path);
    int fido_dev_close(fido_dev_t* dev);
    int fido_dev_set_timeout(fido_dev_t* dev, int milliseconds);

    fido_cred_t* fido_cred_new();
    void fido_cred_free(fido_cred_t** cred);
    int fido_cred_set_type(fido_cred_t* cred, int coseType);
    int fido_cred_set_clientdata_hash(fido_cred_t* cred, const(ubyte)* data, size_t length);
    int fido_cred_set_rp(fido_cred_t* cred, const(char)* id, const(char)* name);
    int fido_cred_set_user(fido_cred_t* cred, const(ubyte)* id, size_t idLength,
        const(char)* name, const(char)* displayName, const(char)* icon);
    int fido_cred_set_extensions(fido_cred_t* cred, int flags);
    int fido_dev_make_cred(fido_dev_t* dev, fido_cred_t* cred, const(char)* pin);
    const(ubyte)* fido_cred_id_ptr(const(fido_cred_t)* cred);
    size_t fido_cred_id_len(const(fido_cred_t)* cred);

    fido_assert_t* fido_assert_new();
    void fido_assert_free(fido_assert_t** assertion);
    int fido_assert_set_clientdata_hash(fido_assert_t* assertion, const(ubyte)* data, size_t length);
    int fido_assert_set_rp(fido_assert_t* assertion, const(char)* id);
    int fido_assert_allow_cred(fido_assert_t* assertion, const(ubyte)* credentialId, size_t credentialIdLength);
    int fido_assert_set_extensions(fido_assert_t* assertion, int flags);
    int fido_assert_set_hmac_salt(fido_assert_t* assertion, const(ubyte)* salt, size_t saltLength);
    int fido_assert_set_up(fido_assert_t* assertion, FidoOpt value);
    int fido_dev_get_assert(fido_dev_t* dev, fido_assert_t* assertion, const(char)* pin);
    size_t fido_assert_count(const(fido_assert_t)* assertion);
    const(ubyte)* fido_assert_hmac_secret_ptr(const(fido_assert_t)* assertion, size_t index);
    size_t fido_assert_hmac_secret_len(const(fido_assert_t)* assertion, size_t index);
}

private void report(Args...)(Args args)
{
    stdout.writeln(args);
    stdout.flush();
}

private string copyCString(const(char)* value)
{
    return value is null ? null : fromStringz(value).idup;
}

private void fail(string operation, int rc)
{
    stderr.writeln("ERROR=", operation, " rc=", rc, " message=", copyCString(fido_strerr(rc)));
    throw new Exception(operation);
}

private char* readHiddenPin()
{
    stderr.writeln("PIN_REQUIRED=Enter authenticator PIN (hidden)");
    stderr.flush();

    if (isatty(STDIN_FILENO) != 1)
        throw new Exception("PIN input requires an interactive terminal");

    termios original;
    if (tcgetattr(STDIN_FILENO, &original) != 0)
        throw new Exception("unable to read terminal settings");

    auto hidden = original;
    hidden.c_lflag &= ~ECHO;

    if (tcsetattr(STDIN_FILENO, TCSANOW, &hidden) != 0)
        throw new Exception("unable to disable terminal echo");

    auto line = stdin.readln();

    const restoreResult = tcsetattr(STDIN_FILENO, TCSANOW, &original);
    stderr.writeln();
    stderr.flush();

    if (restoreResult != 0)
        throw new Exception("unable to restore terminal settings");

    while (line.length != 0 && (line[$ - 1] == '\n' || line[$ - 1] == '\r'))
        line.length -= 1;

    if (line.length == 0)
        throw new Exception("PIN must not be empty");

    auto pin = cast(char*)malloc(line.length + 1);
    if (pin is null)
        throw new Exception("unable to allocate PIN buffer");

    foreach (i, value; line)
        pin[i] = value;
    pin[line.length] = '\0';

    foreach (i; 0 .. line.length)
        line[i] = '\0';

    return pin;
}

private void wipeAndFree(char* pin)
{
    if (pin is null)
        return;

    size_t n;
    while (pin[n] != '\0')
        ++n;

    foreach (i; 0 .. n + 1)
        volatileStore(cast(ubyte*)pin + i, cast(ubyte)0);

    free(pin);
}

private long elapsedMilliseconds(MonoTime start)
{
    return (MonoTime.currTime - start).total!"msecs";
}

int main(string[] args)
{
    enum string rpId = "credentials-d.local";
    enum size_t maximumDevices = 16;

    string explicitDevice;
    if (args.length == 3 && args[1] == "--device")
        explicitDevice = args[2];
    else if (args.length != 1)
    {
        stderr.writeln("usage: dub run -- [--device /dev/hidrawN]");
        return 2;
    }

    fido_init(FIDO_DISABLE_U2F_FALLBACK);

    string devicePath;

    if (explicitDevice.length != 0)
    {
        devicePath = explicitDevice;
    }
    else
    {
        auto list = fido_dev_info_new(maximumDevices);
        if (list is null)
            throw new Exception("fido_dev_info_new failed");
        scope(exit) fido_dev_info_free(&list, maximumDevices);

        size_t count;
        const manifestRc = fido_dev_info_manifest(list, maximumDevices, &count);
        if (manifestRc != FIDO_OK)
            fail("fido_dev_info_manifest", manifestRc);

        report("discovered_devices=", count);

        if (count != 1)
            throw new Exception("expected exactly one FIDO device; use --device otherwise");

        const info = fido_dev_info_ptr(list, 0);
        if (info is null)
            throw new Exception("fido_dev_info_ptr failed");

        devicePath = copyCString(fido_dev_info_path(info));
        report("device=", devicePath,
            " manufacturer=", copyCString(fido_dev_info_manufacturer_string(info)),
            " product=", copyCString(fido_dev_info_product_string(info)));
    }

    char* pin = readHiddenPin();
    scope(exit) wipeAndFree(pin);

    auto dev = fido_dev_new();
    if (dev is null)
        throw new Exception("fido_dev_new failed");
    scope(exit)
    {
        fido_dev_close(dev);
        fido_dev_free(&dev);
    }

    int rc = fido_dev_open(dev, cast(const(char)*)toStringz(devicePath));
    if (rc != FIDO_OK)
        fail("fido_dev_open", rc);

    rc = fido_dev_set_timeout(dev, 30_000);
    if (rc != FIDO_OK)
        fail("fido_dev_set_timeout", rc);

    auto cred = fido_cred_new();
    if (cred is null)
        throw new Exception("fido_cred_new failed");
    scope(exit) fido_cred_free(&cred);

    ubyte[32] clientDataHash;
    ubyte[32] userId;
    foreach (i; 0 .. 32)
    {
        clientDataHash[i] = cast(ubyte)(0x40 + i);
        userId[i] = cast(ubyte)(0x80 + i);
    }

    rc = fido_cred_set_type(cred, COSE_ES256);
    if (rc == FIDO_OK)
        rc = fido_cred_set_clientdata_hash(cred, clientDataHash.ptr, clientDataHash.length);
    if (rc == FIDO_OK)
        rc = fido_cred_set_rp(cred, cast(const(char)*)toStringz(rpId), null);
    if (rc == FIDO_OK)
        rc = fido_cred_set_user(cred, userId.ptr, userId.length,
            cast(const(char)*)toStringz("credentials-d"), null, null);
    if (rc == FIDO_OK)
        rc = fido_cred_set_extensions(cred, FIDO_EXT_HMAC_SECRET);
    if (rc != FIDO_OK)
        fail("configure MakeCredential", rc);

    report("ACTION=MakeCredential starting; wait for blinking, then touch once");

    auto start = MonoTime.currTime;
    rc = fido_dev_make_cred(dev, cred, pin);
    const makeCredentialMs = elapsedMilliseconds(start);

    report("TIMING make_credential_ms=", makeCredentialMs, " rc=", rc);

    if (rc != FIDO_OK)
        fail("fido_dev_make_cred", rc);

    const credentialId = fido_cred_id_ptr(cred);
    const credentialIdLength = fido_cred_id_len(cred);
    if (credentialId is null || credentialIdLength == 0)
        throw new Exception("credential id missing");

    report("credential_id_bytes=", credentialIdLength);

    auto assertion = fido_assert_new();
    if (assertion is null)
        throw new Exception("fido_assert_new failed");
    scope(exit) fido_assert_free(&assertion);

    ubyte[32] assertionClientDataHash;
    ubyte[32] salt;
    foreach (i; 0 .. 32)
    {
        assertionClientDataHash[i] = cast(ubyte)(0x20 + i);
        salt[i] = cast(ubyte)(0xa0 + i);
    }

    rc = fido_assert_set_clientdata_hash(assertion,
        assertionClientDataHash.ptr, assertionClientDataHash.length);
    if (rc == FIDO_OK)
        rc = fido_assert_set_rp(assertion, cast(const(char)*)toStringz(rpId));
    if (rc == FIDO_OK)
        rc = fido_assert_allow_cred(assertion, credentialId, credentialIdLength);
    if (rc == FIDO_OK)
        rc = fido_assert_set_extensions(assertion, FIDO_EXT_HMAC_SECRET);
    if (rc == FIDO_OK)
        rc = fido_assert_set_hmac_salt(assertion, salt.ptr, salt.length);
    if (rc == FIDO_OK)
        rc = fido_assert_set_up(assertion, FidoOpt.true_);
    if (rc != FIDO_OK)
        fail("configure GetAssertion", rc);

    report("ACTION=GetAssertion+hmac-secret starting; wait for blinking, then touch once");

    start = MonoTime.currTime;
    rc = fido_dev_get_assert(dev, assertion, null);
    const getAssertionMs = elapsedMilliseconds(start);

    report("TIMING get_assertion_hmac_secret_ms=", getAssertionMs, " rc=", rc);

    if (rc != FIDO_OK)
        fail("fido_dev_get_assert", rc);

    if (fido_assert_count(assertion) != 1)
        throw new Exception("unexpected assertion count");

    const secret = fido_assert_hmac_secret_ptr(assertion, 0);
    const secretLength = fido_assert_hmac_secret_len(assertion, 0);
    report("hmac_secret_bytes=", secretLength);

    if (secret is null || secretLength != 32)
        throw new Exception("invalid hmac-secret result");

    report("result=PASS");
    return 0;
}
