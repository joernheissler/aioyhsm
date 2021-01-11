from __future__ import annotations

from enum import IntEnum


class Algorithm(IntEnum):
    """
    https://developers.yubico.com/YubiHSM2/Concepts/Algorithms.html
    """

    RSA_PKCS1_SHA1 = 1
    RSA_PKCS1_SHA256 = 2
    RSA_PKCS1_SHA384 = 3
    RSA_PKCS1_SHA512 = 4
    RSA_PSS_SHA1 = 5
    RSA_PSS_SHA256 = 6
    RSA_PSS_SHA384 = 7
    RSA_PSS_SHA512 = 8
    RSA_2048 = 9
    RSA_3072 = 10
    RSA_4096 = 11
    EC_P256 = 12
    EC_P384 = 13
    EC_P521 = 14
    EC_K256 = 15
    EC_BP256 = 16
    EC_BP384 = 17
    EC_BP512 = 18
    HMAC_SHA1 = 19
    HMAC_SHA256 = 20
    HMAC_SHA384 = 21
    HMAC_SHA512 = 22
    ECDSA_SHA1 = 23
    EC_ECDH = 24
    RSA_OAEP_SHA1 = 25
    RSA_OAEP_SHA256 = 26
    RSA_OAEP_SHA384 = 27
    RSA_OAEP_SHA512 = 28
    AES128_CCM_WRAP = 29
    Opaque_Data = 30
    Opaque_X509_Certificate = 31
    MGF1_SHA1 = 32
    MGF1_SHA256 = 33
    MGF1_SHA384 = 34
    MGF1_SHA512 = 35
    SSH_Template = 36
    Yubico_OTP_AES128 = 37
    Yubico_AES_Authentication = 38
    Yubico_OTP_AES192 = 39
    Yubico_OTP_AES256 = 40
    AES192_CCM_WRAP = 41
    AES256_CCM_WRAP = 42
    ECDSA_SHA256 = 43
    ECDSA_SHA384 = 44
    ECDSA_SHA512 = 45
    ED25519 = 46
    EC_P224 = 47


class Capability(IntEnum):
    """
    https://developers.yubico.com/YubiHSM2/Concepts/Capability.html
    """

    GetOpaque = 0
    PutOpaque = 1
    PutAuthenticationKey = 2
    PutAsymmetricKey = 3
    GenerateAsymmetricKey = 4
    SignPkcs = 5
    SignPss = 6
    SignEcdsa = 7
    SignEddsa = 8
    DecryptPkcs = 9
    DecryptOaep = 10
    DeriveEcdh = 11
    ExportWrapped = 12
    ImportWrapped = 13
    PutWrapKey = 14
    GenerateWrapKey = 15
    ExportableUnderWrap = 16
    SetOption = 17
    GetOption = 18
    GetPseudoRandom = 19
    PutMacKey = 20
    GenerateHmacKey = 21
    SignHmac = 22
    VerifyHmac = 23
    GetLogEntries = 24
    SignSshCertificate = 25
    GetTemplate = 26
    PutTemplate = 27
    ResetDevice = 28
    DecryptOtp = 29
    CreateOtpAead = 30
    RandomizeOtpAead = 31
    RewrapFromOtpAeadKey = 32
    RewrapToOtpAeadKey = 33
    SignAttestationCertificate = 34
    PutOtpAeadKey = 35
    GenerateOtpAeadKey = 36
    WrapData = 37
    UnwrapData = 38
    DeleteOpaque = 39
    DeleteAuthenticationKey = 40
    DeleteAsymmetricKey = 41
    DeleteWrapKey = 42
    DeleteHmacKey = 43
    DeleteTemplate = 44
    DeleteOtpAeadKey = 45
    ChangeAuthenticationKey = 46


class Command(IntEnum):
    """
    https://developers.yubico.com/YubiHSM2/Commands/
    """

    Echo = 0x01
    CreateSession = 0x03
    AuthenticateSession = 0x04
    SessionMessage = 0x05
    GetDeviceInfo = 0x06
    ResetDevice = 0x08
    CloseSession = 0x40
    GetStorageInfo = 0x41
    PutOpaque = 0x42
    GetOpaque = 0x43
    PutAuthenticationKey = 0x44
    PutAsymmetricKey = 0x45
    GenerateAsymmetricKey = 0x46
    SignPkcs1 = 0x47
    ListObjects = 0x48
    DecryptPkcs1 = 0x49
    ExportWrapped = 0x4A
    ImportWrapped = 0x4B
    PutWrapKey = 0x4C
    GetLogEntries = 0x4D
    GetObjectInfo = 0x4E
    SetOption = 0x4F
    GetOption = 0x50
    GetPseudoRandom = 0x51
    PutHmacKey = 0x52
    SignHmac = 0x53
    GetPublicKey = 0x54
    SignPss = 0x55
    SignEcdsa = 0x56
    DeriveEcdh = 0x57
    DeleteObject = 0x58
    DecryptOaep = 0x59
    GenerateHmacKey = 0x5A
    GenerateWrapKey = 0x5B
    VerifyHmac = 0x5C
    SignSshCertificate = 0x5D
    PutTemplate = 0x5E
    GetTemplate = 0x5F
    DecryptOtp = 0x60
    CreateOtpAead = 0x61
    RandomizeOtpAead = 0x62
    RewrapOtpAead = 0x63
    SignAttestationCertificate = 0x64
    PutOtpAeadKey = 0x65
    GenerateOtpAeadKey = 0x66
    SetLogIndex = 0x67
    WrapData = 0x68
    UnwrapData = 0x69
    SignEddsa = 0x6A
    BlinkDevice = 0x6B
    ChangeAuthenticationKey = 0x6C
    Error = 0x7F


class Error(IntEnum):
    """
    https://developers.yubico.com/YubiHSM2/Concepts/Errors.html
    """

    OK = 0x00
    INVALID_COMMAND = 0x01
    INVALID_DATA = 0x02
    INVALID_SESSION = 0x03
    AUTHENTICATION_FAILED = 0x04
    SESSIONS_FULL = 0x05
    SESSION_FAILED = 0x06
    STORAGE_FAILED = 0x07
    WRONG_LENGTH = 0x08
    INSUFFICIENT_PERMISSIONS = 0x09
    LOG_FULL = 0x0A
    OBJECT_NOT_FOUND = 0x0B
    INVALID_ID = 0x0C
    SSH_CA_CONSTRAINT_VIOLATION = 0x0E
    INVALID_OTP = 0x0F
    DEMO_MODE = 0x10
    OBJECT_EXISTS = 0x11


class ObjectType(IntEnum):
    """
    https://developers.yubico.com/YubiHSM2/Concepts/Object.html
    """

    Opaque = 0x01
    AuthenticationKey = 0x02
    AsymmetricKey = 0x03
    WrapKey = 0x04
    HmacKey = 0x05
    Template = 0x06
    OtpAeadKey = 0x07


class Option(IntEnum):
    """
    https://developers.yubico.com/YubiHSM2/Concepts/Options.html
    """

    ForceAudit = 0x01
    CommandAudit = 0x03
