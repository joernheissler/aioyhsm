from __future__ import annotations

from dataclasses import astuple, dataclass
from struct import pack, unpack_from
from typing import Annotated, List, Optional, Tuple, get_args, get_type_hints

from .constants import Algorithm, Command, Error
from .log import LogEntry

Uint1 = Annotated[int, 1]
Uint2 = Annotated[int, 2]
Uint8 = Annotated[int, 8]
Bytes6 = Annotated[bytes, 6]
Bytes8 = Annotated[bytes, 8]
Bytes16 = Annotated[bytes, 16]
Bytes36 = Annotated[bytes, 36]
Label = Annotated[bytes, 40]
BytesVar = Annotated[bytes, None]
EncodedAlgorithm = Annotated[Algorithm, 1]
EncodedError = Annotated[Error, 1]

_message_types: Dict[int, Type[Message]] = {}


class Message:
    # Command number
    _cmd: int

    _fields: List[Tuple[str, str, type]]

    _fixed_length: int
    _var_idx: List[int]

    def __init_subclass__(cls, cmd: Optional[Command] = None, **kwargs: Dict[str, Any]) -> None:
        super().__init_subclass__(**kwargs)
        if not cmd:
            return

        cls._fields = []

        cls._fixed_length = 0
        cls._var_idx = []

        # Assume get_type_hints is sorted correctly.
        for idx, (name, value) in enumerate(
            get_type_hints(cls, globalns=globals(), include_extras=True).items()
        ):
            if name[0] == "_":
                continue

            value_type, value_len = get_args(value)
            if issubclass(value_type, int):
                fmt = {1: "B", 2: "H", 4: "L", 8: "Q"}[value_len]
                cls._fixed_length += value_len
            elif issubclass(value_type, bytes):
                if value_len is None:
                    fmt = ""
                    cls._var_idx.append(idx)
                else:
                    fmt = f"{value_len}s"
                    cls._fixed_length += value_len
            else:
                raise TypeError(value_type)

            cls._fields.append((name, fmt, value_type))

        if issubclass(cls, Response):
            cls._cmd = int(cmd) | 0x80
            _message_types[int(cmd) | 0x80] = cls
        elif issubclass(cls, Message):
            cls._cmd = int(cmd)
            _message_types[int(cmd)] = cls
        else:
            raise TypeError(cls)

    def encode(self) -> bytes:
        values = [self._cmd, self._fixed_length]
        fmt = ">BH"

        for field_name, field_fmt, field_type in self._fields:
            value = getattr(self, field_name)
            values.append(value)
            if not field_fmt:
                val_len = len(value)
                field_fmt = f"{val_len}s"
                values[1] += val_len
            fmt += field_fmt

        return pack(fmt, *values)

    @staticmethod
    def decode(message: bytes) -> Message:
        cmd_num, data_len = unpack_from(">BH", message)
        if len(message) != data_len + 3:
            raise ValueError(len(message), data_len)

        cls = _message_types[cmd_num]
        if len(cls._var_idx) == 1:
            var_lengths = [data_len - cls._fixed_length]
        elif len(cls._var_idx) > 1:
            var_lengths = cls.get_lengths(data_len - cls._fixed_length)
        else:
            var_lengths = []

        fmt = ">"
        idx = 0
        types: List[type] = []
        for field_name, field_fmt, field_type in cls._fields:
            if not field_fmt:
                fmt += f"{var_lengths[idx]}s"
                idx += 1
            else:
                fmt += field_fmt

            types.append(field_type)

        return cls(
            *(
                field_type(field_value)
                for field_type, field_value in zip(types, unpack_from(fmt, message, 3))
            )
        )

    @staticmethod
    def get_lengths(msg_len: int) -> List[int]:
        raise NotImplementedError


class Request(Message):
    pass


class Response(Message):
    pass


@dataclass(frozen=True)
class AuthenticateSessionRequest(Request, cmd=Command.AuthenticateSession):
    session_id: Uint1
    host_cryptogram: Bytes8
    mac: Bytes8


@dataclass(frozen=True)
class AuthenticateSessionResponse(Response, cmd=Command.AuthenticateSession):
    """
    x
    """


@dataclass(frozen=True)
class BlinkDeviceRequest(Request, cmd=Command.BlinkDevice):
    seconds: Uint1


@dataclass(frozen=True)
class BlinkDeviceResponse(Response, cmd=Command.BlinkDevice):
    """
    x
    """


@dataclass(frozen=True)
class ChangeAuthenticationKeyRequest(Request, cmd=Command.ChangeAuthenticationKey):
    object_id: Uint2
    algorithm: EncodedAlgorithm
    encryption_key: Bytes16
    mac_key: Bytes16


@dataclass(frozen=True)
class ChangeAuthenticationKeyResponse(Response, cmd=Command.ChangeAuthenticationKey):
    object_id: Uint2


@dataclass(frozen=True)
class CloseSessionRequest(Request, cmd=Command.CloseSession):
    """
    x
    """


@dataclass(frozen=True)
class CloseSessionResponse(Response, cmd=Command.CloseSession):
    """
    x
    """


@dataclass(frozen=True)
class CreateOtpAeadRequest(Request, cmd=Command.CreateOtpAead):
    object_id: Uint2
    otp_key: Bytes16
    otp_id: Bytes6


@dataclass(frozen=True)
class CreateOtpAeadResponse(Response, cmd=Command.CreateOtpAead):
    nonce: Bytes36


@dataclass(frozen=True)
class CreateSessionRequest(Request, cmd=Command.CreateSession):
    key_set_id: Uint2
    host_challenge: Bytes8


@dataclass(frozen=True)
class CreateSessionResponse(Response, cmd=Command.CreateSession):
    session_id: Uint1
    card_challenge: Bytes8
    card_cryptogram: Bytes8


@dataclass(frozen=True)
class DecryptOaepRequest(Request, cmd=Command.DecryptOaep):
    object_id: Uint2
    hash_algorithm: EncodedAlgorithm
    decryption_data: BytesVar
    label_hash: BytesVar

    @staticmethod
    def get_lengths(msg_len: int) -> List[int]:
        data_len = msg_len & ~0x7F
        if data_len not in {256, 384, 512}:
            raise ValueError(msg_len)

        hash_len = msg_len & 0x7F
        if hash_len not in {20, 32, 48, 64}:
            raise ValueError(msg_len)

        return [data_len, hash_len]


@dataclass(frozen=True)
class DecryptOaepResponse(Response, cmd=Command.DecryptOaep):
    data: BytesVar


@dataclass(frozen=True)
class DecryptOtpRequest(Request, cmd=Command.DecryptOtp):
    pass


@dataclass(frozen=True)
class DecryptOtpResponse(Response, cmd=Command.DecryptOtp):
    pass


@dataclass(frozen=True)
class DecryptPkcs1Request(Request, cmd=Command.DecryptPkcs1):
    pass


@dataclass(frozen=True)
class DecryptPkcs1Response(Response, cmd=Command.DecryptPkcs1):
    pass


@dataclass(frozen=True)
class DeleteObjectRequest(Request, cmd=Command.DeleteObject):
    pass


@dataclass(frozen=True)
class DeleteObjectResponse(Response, cmd=Command.DeleteObject):
    pass


@dataclass(frozen=True)
class DeriveEcdhRequest(Request, cmd=Command.DeriveEcdh):
    pass


@dataclass(frozen=True)
class DeriveEcdhResponse(Response, cmd=Command.DeriveEcdh):
    pass


@dataclass(frozen=True)
class EchoRequest(Request, cmd=Command.Echo):
    data: BytesVar


@dataclass(frozen=True)
class EchoResponse(Response, cmd=Command.Echo):
    data: BytesVar


@dataclass(frozen=True)
class ExportWrappedRequest(Request, cmd=Command.ExportWrapped):
    pass


@dataclass(frozen=True)
class ExportWrappedResponse(Response, cmd=Command.ExportWrapped):
    pass


@dataclass(frozen=True)
class GenerateAsymmetricKeyRequest(Request, cmd=Command.GenerateAsymmetricKey):
    object_id: Uint2
    label: Label
    domains: Uint2
    capabilities: Uint8
    algorithm: EncodedAlgorithm


@dataclass(frozen=True)
class GenerateAsymmetricKeyResponse(Response, cmd=Command.GenerateAsymmetricKey):
    object_id: Uint2


@dataclass(frozen=True)
class GenerateHmacKeyRequest(Request, cmd=Command.GenerateHmacKey):
    pass


@dataclass(frozen=True)
class GenerateHmacKeyResponse(Response, cmd=Command.GenerateHmacKey):
    pass


@dataclass(frozen=True)
class GenerateOtpAeadKeyRequest(Request, cmd=Command.GenerateOtpAeadKey):
    pass


@dataclass(frozen=True)
class GenerateOtpAeadKeyResponse(Response, cmd=Command.GenerateOtpAeadKey):
    pass


@dataclass(frozen=True)
class GenerateWrapKeyRequest(Request, cmd=Command.GenerateWrapKey):
    pass


@dataclass(frozen=True)
class GenerateWrapKeyResponse(Response, cmd=Command.GenerateWrapKey):
    pass


@dataclass(frozen=True)
class GetDeviceInfoRequest(Request, cmd=Command.GetDeviceInfo):
    pass


@dataclass(frozen=True)
class GetDeviceInfoResponse(Response, cmd=Command.GetDeviceInfo):
    pass


@dataclass(frozen=True)
class GetLogEntriesRequest(Request, cmd=Command.GetLogEntries):
    """
    x
    """


@dataclass(frozen=True)
class GetLogEntriesResponse(Response, cmd=Command.GetLogEntries):
    unlogged_boot_events: Uint2
    unlogged_auth_events: Uint2
    entry_count: Uint1
    entries: BytesVar

    @property
    def parsed_entries(self) -> List[LogEntry]:
        if len(self.entries) != 32 * self.entry_count:
            raise Exception(
                f"Inconsistent entry count: {self.entry_count} with length {len(self.entries)}"
            )

        return [
            LogEntry.decode(self.entries[idx * 32 : (idx + 1) * 32])
            for idx in range(self.entry_count)
        ]


@dataclass(frozen=True)
class GetObjectInfoRequest(Request, cmd=Command.GetObjectInfo):
    pass


@dataclass(frozen=True)
class GetObjectInfoResponse(Response, cmd=Command.GetObjectInfo):
    pass


@dataclass(frozen=True)
class GetOpaqueRequest(Request, cmd=Command.GetOpaque):
    pass


@dataclass(frozen=True)
class GetOpaqueResponse(Response, cmd=Command.GetOpaque):
    pass


@dataclass(frozen=True)
class GetOptionRequest(Request, cmd=Command.GetOption):
    pass


@dataclass(frozen=True)
class GetOptionResponse(Response, cmd=Command.GetOption):
    pass


@dataclass(frozen=True)
class GetPseudoRandomRequest(Request, cmd=Command.GetPseudoRandom):
    count: Uint2


@dataclass(frozen=True)
class GetPseudoRandomResponse(Response, cmd=Command.GetPseudoRandom):
    random: BytesVar


@dataclass(frozen=True)
class GetPublicKeyRequest(Request, cmd=Command.GetPublicKey):
    object_id: Uint2


@dataclass(frozen=True)
class GetPublicKeyResponse(Response, cmd=Command.GetPublicKey):
    algorithm: EncodedAlgorithm
    public: BytesVar


@dataclass(frozen=True)
class GetStorageInfoRequest(Request, cmd=Command.GetStorageInfo):
    """
    x
    """


@dataclass(frozen=True)
class GetStorageInfoResponse(Response, cmd=Command.GetStorageInfo):
    records_total: Uint2
    records_free: Uint2
    pages_total: Uint2
    pages_free: Uint2
    page_size: Uint2


@dataclass(frozen=True)
class GetTemplateRequest(Request, cmd=Command.GetTemplate):
    pass


@dataclass(frozen=True)
class GetTemplateResponse(Response, cmd=Command.GetTemplate):
    pass


@dataclass(frozen=True)
class ImportWrappedRequest(Request, cmd=Command.ImportWrapped):
    pass


@dataclass(frozen=True)
class ImportWrappedResponse(Response, cmd=Command.ImportWrapped):
    pass


@dataclass(frozen=True)
class ListObjectsRequest(Request, cmd=Command.ListObjects):
    pass


@dataclass(frozen=True)
class ListObjectsResponse(Response, cmd=Command.ListObjects):
    pass


@dataclass(frozen=True)
class PutAsymmetricKeyRequest(Request, cmd=Command.PutAsymmetricKey):
    object_id: Uint2
    label: Label
    domains: Uint2
    capabilities: Uint8
    algorithm: EncodedAlgorithm
    param: BytesVar


@dataclass(frozen=True)
class PutAsymmetricKeyResponse(Response, cmd=Command.PutAsymmetricKey):
    object_id: Uint2


@dataclass(frozen=True)
class PutAuthenticationKeyRequest(Request, cmd=Command.PutAuthenticationKey):
    object_id: Uint2
    label: Label
    domains: Uint2
    capabilities: Uint8
    algorithm: EncodedAlgorithm
    delegated_capabilities: Uint8
    encryption_key: Bytes16
    mac_key: Bytes16


@dataclass(frozen=True)
class PutAuthenticationKeyResponse(Response, cmd=Command.PutAuthenticationKey):
    object_id: Uint2


@dataclass(frozen=True)
class PutHmacKeyRequest(Request, cmd=Command.PutHmacKey):
    pass


@dataclass(frozen=True)
class PutHmacKeyResponse(Response, cmd=Command.PutHmacKey):
    pass


@dataclass(frozen=True)
class PutOpaqueRequest(Request, cmd=Command.PutOpaque):
    pass


@dataclass(frozen=True)
class PutOpaqueResponse(Response, cmd=Command.PutOpaque):
    pass


@dataclass(frozen=True)
class PutOtpAeadKeyRequest(Request, cmd=Command.PutOtpAeadKey):
    pass


@dataclass(frozen=True)
class PutOtpAeadKeyResponse(Response, cmd=Command.PutOtpAeadKey):
    pass


@dataclass(frozen=True)
class PutTemplateRequest(Request, cmd=Command.PutTemplate):
    pass


@dataclass(frozen=True)
class PutTemplateResponse(Response, cmd=Command.PutTemplate):
    pass


@dataclass(frozen=True)
class PutWrapKeyRequest(Request, cmd=Command.PutWrapKey):
    pass


@dataclass(frozen=True)
class PutWrapKeyResponse(Response, cmd=Command.PutWrapKey):
    pass


@dataclass(frozen=True)
class RandomizeOtpAeadRequest(Request, cmd=Command.RandomizeOtpAead):
    pass


@dataclass(frozen=True)
class RandomizeOtpAeadResponse(Response, cmd=Command.RandomizeOtpAead):
    pass


@dataclass(frozen=True)
class ResetDeviceRequest(Request, cmd=Command.ResetDevice):
    pass


@dataclass(frozen=True)
class ResetDeviceResponse(Response, cmd=Command.ResetDevice):
    pass


@dataclass(frozen=True)
class RewrapOtpAeadRequest(Request, cmd=Command.RewrapOtpAead):
    pass


@dataclass(frozen=True)
class RewrapOtpAeadResponse(Response, cmd=Command.RewrapOtpAead):
    pass


@dataclass(frozen=True)
class SessionMessageRequest(Request, cmd=Command.SessionMessage):
    session_id: Uint1
    inner: BytesVar
    mac: Bytes8


@dataclass(frozen=True)
class SessionMessageResponse(Response, cmd=Command.SessionMessage):
    session_id: Uint1
    inner: BytesVar
    mac: Bytes8


@dataclass(frozen=True)
class SetLogIndexRequest(Request, cmd=Command.SetLogIndex):
    log_index: Uint2


@dataclass(frozen=True)
class SetLogIndexResponse(Response, cmd=Command.SetLogIndex):
    """
    x
    """


@dataclass(frozen=True)
class SetOptionRequest(Request, cmd=Command.SetOption):
    pass


@dataclass(frozen=True)
class SetOptionResponse(Response, cmd=Command.SetOption):
    pass


@dataclass(frozen=True)
class SignAttestationCertificateRequest(Request, cmd=Command.SignAttestationCertificate):
    pass


@dataclass(frozen=True)
class SignAttestationCertificateResponse(Response, cmd=Command.SignAttestationCertificate):
    pass


@dataclass(frozen=True)
class SignEcdsaRequest(Request, cmd=Command.SignEcdsa):
    pass


@dataclass(frozen=True)
class SignEcdsaResponse(Response, cmd=Command.SignEcdsa):
    pass


@dataclass(frozen=True)
class SignEddsaRequest(Request, cmd=Command.SignEddsa):
    pass


@dataclass(frozen=True)
class SignEddsaResponse(Response, cmd=Command.SignEddsa):
    pass


@dataclass(frozen=True)
class SignHmacRequest(Request, cmd=Command.SignHmac):
    pass


@dataclass(frozen=True)
class SignHmacResponse(Response, cmd=Command.SignHmac):
    pass


@dataclass(frozen=True)
class SignPkcs1Request(Request, cmd=Command.SignPkcs1):
    object_id: Uint2
    digest: BytesVar


@dataclass(frozen=True)
class SignPkcs1Response(Response, cmd=Command.SignPkcs1):
    signature: BytesVar


@dataclass(frozen=True)
class SignPssRequest(Request, cmd=Command.SignPss):
    object_id: Uint2
    algorithm: EncodedAlgorithm
    hash_length: Uint2
    digest: BytesVar


@dataclass(frozen=True)
class SignPssResponse(Response, cmd=Command.SignPss):
    signature: BytesVar


@dataclass(frozen=True)
class SignSshCertificateRequest(Request, cmd=Command.SignSshCertificate):
    pass


@dataclass(frozen=True)
class SignSshCertificateResponse(Response, cmd=Command.SignSshCertificate):
    pass


@dataclass(frozen=True)
class UnwrapDataRequest(Request, cmd=Command.UnwrapData):
    pass


@dataclass(frozen=True)
class UnwrapDataResponse(Response, cmd=Command.UnwrapData):
    pass


@dataclass(frozen=True)
class VerifyHmacRequest(Request, cmd=Command.VerifyHmac):
    pass


@dataclass(frozen=True)
class VerifyHmacResponse(Response, cmd=Command.VerifyHmac):
    pass


@dataclass(frozen=True)
class WrapDataRequest(Request, cmd=Command.WrapData):
    pass


@dataclass(frozen=True)
class WrapDataResponse(Response, cmd=Command.WrapData):
    pass


@dataclass(frozen=True)
class ErrorMessage(Message, cmd=Command.Error):
    code: EncodedError
