/**
 * Linux/POSIX persistence primitives for encrypted vault images.
 *
 * These helpers operate only on encrypted bytes. No credential plaintext is
 * ever written by this module.
 */
module credentials.backend.vault.posix_file;

version (linux):

import core.stdc.errno :
    EACCES,
    EEXIST,
    EINTR,
    ELOOP,
    ENOENT,
    EPERM,
    errno;
import core.stdc.stdio : rename;
import core.sys.linux.sys.file :
    LOCK_EX,
    LOCK_UN,
    flock;
import core.sys.posix.fcntl :
    O_CLOEXEC,
    O_CREAT,
    O_DIRECTORY,
    O_EXCL,
    O_NOFOLLOW,
    O_RDONLY,
    O_RDWR,
    O_WRONLY,
    open;
import core.sys.posix.sys.stat :
    S_IRUSR,
    S_IRWXG,
    S_IRWXO,
    S_IWGRP,
    S_IWOTH,
    S_IWUSR,
    S_ISDIR,
    S_ISREG,
    fstat,
    lstat,
    stat_t;
import core.sys.posix.unistd :
    close,
    geteuid,
    link,
    read,
    unlink,
    write;
import credentials.backend.vault.core : maximumVaultImageBytes;
import credentials.random : generateSecureLocator;
import std.path : dirName;
import std.string : toStringz;

extern(C) @nogc nothrow
int fsync(int fd);

package(credentials.backend.vault):

enum VaultFileStatus
{
    ok,
    notFound,
    alreadyExists,
    permissionDenied,
    unsafeState,
    tooLarge,
    commitUncertain,
    ioFailure
}

struct VaultFileLock
{
    private int fd_ = -1;

    @disable this(this);

    @property bool valid() const scope @nogc nothrow @safe
    {
        return fd_ >= 0;
    }

    void release() scope @nogc nothrow @trusted
    {
        if (fd_ < 0)
            return;

        flock(fd_, LOCK_UN);
        close(fd_);
        fd_ = -1;
    }

    ~this() scope @nogc nothrow @trusted
    {
        release();
    }
}

private VaultFileStatus errnoStatus(int value)
    @nogc nothrow @safe
{
    if (value == ENOENT)
        return VaultFileStatus.notFound;
    if (value == EACCES || value == EPERM || value == ELOOP)
        return VaultFileStatus.permissionDenied;
    if (value == EEXIST)
        return VaultFileStatus.alreadyExists;
    return VaultFileStatus.ioFailure;
}

private VaultFileStatus verifyRegularOwnerOnly(int fd)
    @trusted
{
    stat_t info;
    if (fstat(fd, &info) != 0)
        return VaultFileStatus.ioFailure;

    if (!S_ISREG(info.st_mode))
        return VaultFileStatus.unsafeState;

    if (info.st_uid != geteuid())
        return VaultFileStatus.permissionDenied;

    if ((info.st_mode & (S_IRWXG | S_IRWXO)) != 0)
        return VaultFileStatus.permissionDenied;

    return VaultFileStatus.ok;
}

private VaultFileStatus verifyPrivateParent(string path)
    @trusted
{
    const parent = dirName(path);
    const parentZ = toStringz(parent);

    const fd = open(
        parentZ,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    );
    if (fd < 0)
        return errnoStatus(errno);

    scope(exit) close(fd);

    stat_t info;
    if (fstat(fd, &info) != 0)
        return VaultFileStatus.ioFailure;

    if (!S_ISDIR(info.st_mode))
        return VaultFileStatus.unsafeState;

    if (info.st_uid != geteuid())
        return VaultFileStatus.permissionDenied;

    if ((info.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        return VaultFileStatus.permissionDenied;

    return VaultFileStatus.ok;
}

private bool writeAll(int fd, scope const(ubyte)[] data)
    @trusted
{
    size_t offset;

    while (offset < data.length)
    {
        const written = write(
            fd,
            data.ptr + offset,
            data.length - offset
        );

        if (written < 0)
        {
            if (errno == EINTR)
                continue;
            return false;
        }

        if (written == 0)
            return false;

        offset += cast(size_t) written;
    }

    return true;
}

private bool readAll(int fd, scope ubyte[] data)
    @trusted
{
    size_t offset;

    while (offset < data.length)
    {
        const count = read(
            fd,
            data.ptr + offset,
            data.length - offset
        );

        if (count < 0)
        {
            if (errno == EINTR)
                continue;
            return false;
        }

        if (count == 0)
            return false;

        offset += cast(size_t) count;
    }

    return true;
}

private VaultFileStatus syncParent(string path)
    @trusted
{
    const parent = dirName(path);
    const parentZ = toStringz(parent);

    const fd = open(
        parentZ,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    );
    if (fd < 0)
        return errnoStatus(errno);

    scope(exit) close(fd);

    if (fsync(fd) != 0)
        return VaultFileStatus.ioFailure;

    return VaultFileStatus.ok;
}

/**
 * Acquire the stable sidecar lock for one vault path.
 */
VaultFileStatus acquireVaultFileLock(
    string vaultPath,
    out VaultFileLock result
) @trusted
{
    result = VaultFileLock.init;

    auto status = verifyPrivateParent(vaultPath);
    if (status != VaultFileStatus.ok)
        return status;

    const lockPath = vaultPath ~ ".lock";
    const lockZ = toStringz(lockPath);

    const fd = open(
        lockZ,
        O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
        cast(uint)(S_IRUSR | S_IWUSR)
    );
    if (fd < 0)
        return errnoStatus(errno);

    status = verifyRegularOwnerOnly(fd);
    if (status != VaultFileStatus.ok)
    {
        close(fd);
        return status;
    }

    while (flock(fd, LOCK_EX) != 0)
    {
        if (errno == EINTR)
            continue;

        close(fd);
        return VaultFileStatus.ioFailure;
    }

    // Re-check the pathname after locking so accidental replacement of the
    // stable lock file is detected rather than silently using an unlinked inode.
    stat_t fdInfo;
    stat_t pathInfo;

    if (fstat(fd, &fdInfo) != 0 ||
        lstat(lockZ, &pathInfo) != 0 ||
        fdInfo.st_dev != pathInfo.st_dev ||
        fdInfo.st_ino != pathInfo.st_ino ||
        !S_ISREG(pathInfo.st_mode))
    {
        flock(fd, LOCK_UN);
        close(fd);
        return VaultFileStatus.unsafeState;
    }

    result.fd_ = fd;
    return VaultFileStatus.ok;
}

/**
 * Read one bounded encrypted vault image.
 *
 * Caller holds VaultFileLock.
 */
VaultFileStatus readVaultImage(
    string vaultPath,
    out ubyte[] image
) @trusted
{
    image = null;

    const pathZ = toStringz(vaultPath);
    const fd = open(
        pathZ,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW
    );

    if (fd < 0)
        return errnoStatus(errno);

    scope(exit) close(fd);

    auto status = verifyRegularOwnerOnly(fd);
    if (status != VaultFileStatus.ok)
        return status;

    stat_t info;
    if (fstat(fd, &info) != 0)
        return VaultFileStatus.ioFailure;

    if (info.st_size < 0)
        return VaultFileStatus.unsafeState;

    const size = cast(ulong) info.st_size;
    if (size == 0)
        return VaultFileStatus.unsafeState;

    if (size > maximumVaultImageBytes || size > size_t.max)
        return VaultFileStatus.tooLarge;

    image = new ubyte[cast(size_t) size];

    if (!readAll(fd, image))
    {
        image = null;
        return VaultFileStatus.ioFailure;
    }

    return VaultFileStatus.ok;
}

private VaultFileStatus writeEncryptedTemp(
    string vaultPath,
    scope const(ubyte)[] image,
    out string tempPath
) @trusted
{
    tempPath = null;

    if (image.length == 0 || image.length > maximumVaultImageBytes)
        return VaultFileStatus.tooLarge;

    string random;
    if (!generateSecureLocator(random))
        return VaultFileStatus.ioFailure;

    tempPath = vaultPath ~ ".tmp-" ~ random;
    const tempZ = toStringz(tempPath);

    const fd = open(
        tempZ,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        cast(uint)(S_IRUSR | S_IWUSR)
    );
    if (fd < 0)
        return errnoStatus(errno);

    bool keepTemp;
    scope(exit)
    {
        close(fd);
        if (!keepTemp)
            unlink(tempZ);
    }

    auto status = verifyRegularOwnerOnly(fd);
    if (status != VaultFileStatus.ok)
        return status;

    if (!writeAll(fd, image))
        return VaultFileStatus.ioFailure;

    if (fsync(fd) != 0)
        return VaultFileStatus.ioFailure;

    keepTemp = true;
    return VaultFileStatus.ok;
}

/**
 * Create a vault without replacing an existing final path.
 *
 * Caller holds VaultFileLock.
 */
VaultFileStatus createVaultImage(
    string vaultPath,
    scope const(ubyte)[] image
) @trusted
{
    auto status = verifyPrivateParent(vaultPath);
    if (status != VaultFileStatus.ok)
        return status;

    string tempPath;
    status = writeEncryptedTemp(vaultPath, image, tempPath);
    if (status != VaultFileStatus.ok)
        return status;

    const tempZ = toStringz(tempPath);
    const pathZ = toStringz(vaultPath);

    scope(exit) unlink(tempZ);

    // Hard-linking a complete same-directory temporary file is an atomic
    // no-replace commit: an existing final entry makes link() fail.
    if (link(tempZ, pathZ) != 0)
        return errnoStatus(errno);

    status = syncParent(vaultPath);
    if (status != VaultFileStatus.ok)
        return VaultFileStatus.commitUncertain;

    // Once the final name is durable, a cleanup failure can only leave an
    // additional encrypted temporary hard-link. It does not make the vault
    // commit ambiguous.
    if (unlink(tempZ) == 0)
        syncParent(vaultPath);

    return VaultFileStatus.ok;
}

/**
 * Atomically replace an already validated vault image.
 *
 * Caller holds VaultFileLock and has read/validated the current final file.
 */
VaultFileStatus replaceVaultImage(
    string vaultPath,
    scope const(ubyte)[] image
) @trusted
{
    auto status = verifyPrivateParent(vaultPath);
    if (status != VaultFileStatus.ok)
        return status;

    string tempPath;
    status = writeEncryptedTemp(vaultPath, image, tempPath);
    if (status != VaultFileStatus.ok)
        return status;

    const tempZ = toStringz(tempPath);
    const pathZ = toStringz(vaultPath);

    bool renamed;
    scope(exit)
    {
        if (!renamed)
            unlink(tempZ);
    }

    if (rename(tempZ, pathZ) != 0)
        return errnoStatus(errno);

    renamed = true;

    status = syncParent(vaultPath);
    if (status != VaultFileStatus.ok)
        return VaultFileStatus.commitUncertain;

    return VaultFileStatus.ok;
}
