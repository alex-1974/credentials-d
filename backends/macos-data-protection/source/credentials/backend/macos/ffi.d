/**
 * Narrow CoreFoundation/Security ABI surface used by the macOS backend.
 */
module credentials.backend.macos.ffi;

version (OSX):

alias CFIndex = long;
alias CFTypeID = size_t;
alias CFStringEncoding = uint;
alias Boolean = ubyte;
alias OSStatus = int;

alias CFAllocatorRef = const(void)*;
alias CFTypeRef = const(void)*;
alias CFStringRef = const(void)*;
alias CFDataRef = const(void)*;
alias CFDictionaryRef = const(void)*;
alias CFMutableDictionaryRef = void*;

enum CFStringEncoding kCFStringEncodingUTF8 = 0x08000100;

struct CFDictionaryKeyCallBacks
{
    CFIndex version_;
    void* retain;
    void* release;
    void* copyDescription;
    void* equal;
    void* hash;
}

struct CFDictionaryValueCallBacks
{
    CFIndex version_;
    void* retain;
    void* release;
    void* copyDescription;
    void* equal;
}

enum OSStatus errSecSuccess = 0;
enum OSStatus errSecParam = -50;
enum OSStatus errSecUserCanceled = -128;
enum OSStatus errSecMissingEntitlement = -34018;
enum OSStatus errSecRestrictedAPI = -34020;
enum OSStatus errSecNotAvailable = -25291;
enum OSStatus errSecReadOnly = -25292;
enum OSStatus errSecAuthFailed = -25293;
enum OSStatus errSecDuplicateItem = -25299;
enum OSStatus errSecItemNotFound = -25300;
enum OSStatus errSecDataTooLarge = -25302;
enum OSStatus errSecInteractionNotAllowed = -25308;
enum OSStatus errSecInteractionRequired = -25315;
enum OSStatus errSecDataNotAvailable = -25316;
enum OSStatus errSecDecode = -26275;

extern(C) @nogc nothrow
{
    // CoreFoundation.
    CFMutableDictionaryRef CFDictionaryCreateMutable(
        CFAllocatorRef allocator,
        CFIndex capacity,
        const CFDictionaryKeyCallBacks* keyCallbacks,
        const CFDictionaryValueCallBacks* valueCallbacks
    );
    void CFDictionarySetValue(
        CFMutableDictionaryRef dictionary,
        const(void)* key,
        const(void)* value
    );

    CFStringRef CFStringCreateWithCString(
        CFAllocatorRef allocator,
        scope const(char)* cString,
        CFStringEncoding encoding
    );

    CFDataRef CFDataCreate(
        CFAllocatorRef allocator,
        scope const(ubyte)* bytes,
        CFIndex length
    );
    CFIndex CFDataGetLength(CFDataRef data);
    const(ubyte)* CFDataGetBytePtr(CFDataRef data);
    CFTypeID CFDataGetTypeID();
    CFTypeID CFGetTypeID(CFTypeRef value);
    void CFRelease(CFTypeRef value);

    // Security.framework.
    OSStatus SecItemAdd(
        CFDictionaryRef attributes,
        CFTypeRef* result
    );
    OSStatus SecItemCopyMatching(
        CFDictionaryRef query,
        CFTypeRef* result
    );
    OSStatus SecItemUpdate(
        CFDictionaryRef query,
        CFDictionaryRef attributesToUpdate
    );
    OSStatus SecItemDelete(CFDictionaryRef query);
}

extern(C) __gshared
{
    // CoreFoundation exported values/callback tables.
    CFTypeRef kCFBooleanTrue;
    CFTypeRef kCFBooleanFalse;
    CFDictionaryKeyCallBacks kCFTypeDictionaryKeyCallBacks;
    CFDictionaryValueCallBacks kCFTypeDictionaryValueCallBacks;

    // Security item constants.
    CFTypeRef kSecClass;
    CFTypeRef kSecClassGenericPassword;
    CFTypeRef kSecAttrService;
    CFTypeRef kSecAttrAccount;
    CFTypeRef kSecAttrSynchronizable;
    CFTypeRef kSecAttrAccessible;
    CFTypeRef kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
    CFTypeRef kSecValueData;
    CFTypeRef kSecReturnData;
    CFTypeRef kSecMatchLimit;
    CFTypeRef kSecMatchLimitOne;
    CFTypeRef kSecUseDataProtectionKeychain;
}
