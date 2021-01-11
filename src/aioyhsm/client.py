from __future__ import annotations

from contextlib import AsyncExitStack, asynccontextmanager
from os import urandom
from struct import pack
from typing import AnyStr, ByteString, Type, TypeVar

import httpx

from . import constants, crypto, messages
from .error import YubiHsmError

ResponseType = TypeVar("ResponseType", bound="messages.Response")


def encode_label(label: AnyStr) -> bytes:
    tmp = label.encode() if isinstance(label, str) else bytes(label)
    if len(tmp) > 40:
        raise ValueError
    return tmp.ljust(40, b"\0")


def encode_domains(domains: Set[int]) -> int:
    return sum(1 << domain for domain in domains)


def encode_capabilities(capabilities: Set[constants.Capability]) -> int:
    return sum(1 << capa for capa in capabilities)


class YubiHsmClient:
    def __init__(self, url: str) -> None:
        self.url = url

    async def __aenter__(self) -> YubiHsmClient:
        self._stack = await AsyncExitStack().__aenter__()
        self._http = await self._stack.enter_async_context(httpx.AsyncClient())

        return self

    async def __aexit__(self, exc_type, exc, tb):
        return await self._stack.__aexit__(exc_type, exc, tb)

    @asynccontextmanager
    async def open_session_password(self, key_id: int, password: AnyStr) -> YubiHsmSession:
        async with self.open_session_symmetric(
            key_id, *crypto.derive_password(password)
        ) as session:
            yield session

    @asynccontextmanager
    async def open_session_symmetric(
        self, key_id: int, enc_key: ByteString, mac_key: ByteString
    ) -> YubiHsmSession:
        host_challenge = urandom(8)
        create_resp = await self.create_session(key_id, host_challenge)
        sid = create_resp.session_id
        skey = crypto.SessionKeys(enc_key, mac_key, host_challenge, create_resp.card_challenge)

        if not crypto.bytes_eq(skey.card_cryptogram, create_resp.card_cryptogram):
            raise Exception("Authentication error")

        auth_req = messages.AuthenticateSessionRequest(sid, skey.host_cryptogram, bytes(8))
        mac = skey.calc_host_mac(auth_req.encode()[:-8])
        auth_resp = await self.authenticate_session(sid, skey.host_cryptogram, mac)
        session = YubiHsmSession(self, sid, skey)
        yield session
        await session.close_session()

    async def query(self, request: messages.Request, rtype: Type[ResponseType]) -> ResponseType:
        resp = await self._http.post(
            self.url + "/connector/api", content=request.encode(), allow_redirects=False
        )
        resp.raise_for_status()
        response = messages.Message.decode(resp.content)

        if not isinstance(response, rtype):
            if isinstance(response, messages.ErrorMessage):
                raise YubiHsmError(response.code)
            else:
                raise TypeError(type(response))
        return response

    async def authenticate_session(
        self, session_id: int, host_cryptogram: ByteString, mac: ByteString
    ) -> messages.AuthenticateSessionResponse:
        msg = messages.AuthenticateSessionRequest(session_id, host_cryptogram, mac)
        return await self.query(msg, messages.AuthenticateSessionResponse)

    async def create_session(
        self, key_set_id: int, host_challenge: ByteString
    ) -> messages.CreateSessionResponse:
        msg = messages.CreateSessionRequest(key_set_id, host_challenge)
        return await self.query(msg, messages.CreateSessionResponse)

    async def echo(self, data: ByteString) -> messages.EchoResponse:
        msg = messages.EchoRequest(data)
        return await self.query(msg, messages.EchoResponse)

    async def session_message(
        self, session_id: int, inner: ByteString, mac: ByteString
    ) -> messages.SessionMessageResponse:
        msg = messages.SessionMessageRequest(session_id, inner, mac)
        return await self.query(msg, messages.SessionMessageResponse)


class YubiHsmSession:
    """"""

    client: YubiHsmClient
    session_id: int
    _session_keys: crypto.SessionKeys

    def __init__(
        self, client: YubiHsmClient, session_id: int, session_keys: crypto.SessionKeys
    ) -> None:
        self.client = client
        self.session_id = session_id
        self._session_keys = session_keys

    async def query(self, request: messages.Request, rtype: Type[ResponseType]) -> ResponseType:
        iv, enc_msg = self._session_keys.encrypt(request.encode())
        tmp = messages.SessionMessageRequest(self.session_id, enc_msg, bytes(8))
        req_mac = self._session_keys.calc_host_mac(tmp.encode()[:-8])
        enc_rsp = await self.client.session_message(self.session_id, enc_msg, req_mac)
        rsp_mac = self._session_keys.calc_card_mac(enc_rsp.encode()[:-8])
        if not crypto.bytes_eq(rsp_mac, enc_rsp.mac):
            raise Exception
        if self.session_id != enc_rsp.session_id:
            raise Exception

        raw_response = self._session_keys.decrypt(iv, enc_rsp.inner)
        response = messages.Message.decode(raw_response)
        if not isinstance(response, rtype):
            if isinstance(response, messages.ErrorMessage):
                raise YubiHsmError(response.code)
            else:
                raise TypeError(type(response))
        return response

    async def blink_device(self, seconds: int) -> messages.BlinkDeviceResponse:
        msg = messages.BlinkDeviceRequest(seconds)
        return await self.query(msg, messages.BlinkDeviceResponse)

    async def close_session(self) -> messages.CloseSessionResponse:
        msg = messages.CloseSessionRequest()
        return await self.query(msg, messages.CloseSessionResponse)

    async def echo(self, data: ByteString) -> messages.EchoResponse:
        msg = messages.EchoRequest(data)
        return await self.query(msg, messages.EchoResponse)

    async def generate_asymmetric_key(
        self,
        object_id: int,
        label: AnyString,
        domains: Set[int],
        capabilities: Set[constants.Capability],
        algorithm: constants.Algorithm,
    ) -> messages.GenerateAsymmetricKeyResponse:
        msg = messages.GenerateAsymmetricKeyRequest(
            object_id,
            encode_label(label),
            encode_domains(domains),
            encode_capabilities(capabilities),
            algorithm,
        )
        return await self.query(msg, messages.GenerateAsymmetricKeyResponse)

    async def get_log_entries(self) -> messages.GetLogEntriesResponse:
        msg = messages.GetLogEntriesRequest()
        return await self.query(msg, messages.GetLogEntriesResponse)

    async def get_pseudo_random(self, count: int) -> messages.GetPseudoRandomResponse:
        msg = messages.GetPseudoRandomRequest(count)
        return await self.query(msg, messages.GetPseudoRandomResponse)

    async def get_public_key(self, object_id: int) -> messages.GetPublicKeyResponse:
        msg = messages.GetPublicKeyRequest(object_id)
        return await self.query(msg, messages.GetPublicKeyResponse)

    async def get_storage_info(self) -> messages.GetStorageInfoResponse:
        msg = messages.GetStorageInfoRequest()
        return await self.query(msg, messages.GetStorageInfoResponse)

    async def set_log_index(self, log_index: int) -> messages.SetLogIndexResponse:
        msg = messages.SetLogIndexRequest(log_index)
        return await self.query(msg, messages.SetLogIndexResponse)

    async def sign_pkcs1(
        self, object_id: int, digest: ByteString
    ) -> messages.SignPkcs1Response:
        msg = messages.SignPkcs1Request(object_id, digest)
        return await self.query(msg, messages.SignPkcs1Response)

    async def sign_pss(
        self,
        object_id: int,
        hash_algorithm: constants.Algorithm,
        hash_length: int,
        digest: ByteString,
    ) -> messages.SignPssResponse:
        msg = messages.SignPssRequest(object_id, hash_algorithm, hash_length, digest)
        return await self.query(msg, messages.SignPssResponse)

    async def put_asymmetric_key(
        self,
        object_id: int,
        label: AnyString,
        domains: Set[int],
        capabilities: Set[constants.Capability],
        algorithm: constants.Algorithm,
        parameter: ByteString,
    ) -> messages.PutAsymmetricKeyResponse:
        msg = messages.PutAsymmetricKeyRequest(
            object_id,
            encode_label(label),
            encode_domains(domains),
            encode_capabilities(capabilities),
            algorithm,
            parameter,
        )
        return await self.query(msg, messages.PutAsymmetricKeyResponse)

    async def put_rsa_key(
        self,
        object_id: int,
        label: AnyString,
        domains: Set[int],
        prime0: int,
        prime1: int,
        exportable: bool,
        *,
        sign_pkcs: bool = False,
        sign_pss: bool = False,
        sign_ssh_cert: bool = False,
        decrypt_pkcs: bool = False,
        decrypt_oaep: bool = False,
    ) -> messages.PutAsymmetricKeyResponse:
        capabilities = {
            capa
            for flag, capa in [
                (exportable, constants.Capability.ExportableUnderWrap),
                (sign_pkcs, constants.Capability.SignPkcs),
                (sign_pss, constants.Capability.SignPss),
                (sign_ssh_cert, constants.Capability.SignSshCertificate),
                (decrypt_pkcs, constants.Capability.DecryptPkcs),
                (decrypt_oaep, constants.Capability.DecryptOaep),
            ]
            if flag
        }

        bits = prime0.bit_length()
        if bits != prime1.bit_length():
            raise ValueError(f"Primes have different lengths: {bits} != {prime1.bit_length()}")

        try:
            algorithm = {
                1024: constants.Algorithm.RSA_2048,
                1536: constants.Algorithm.RSA_3072,
                2048: constants.Algorithm.RSA_4096,
            }[bits]
        except KeyError as ex:
            raise ValueError(f"Primes must be 1024, 1536 or 2048 bit, not {bits}") from ex

        param = prime0.to_bytes(bits // 8, "big") + prime1.to_bytes(bits // 8, "big")
        return await self.put_asymmetric_key(
            object_id, label, domains, capabilities, algorithm, param
        )

    async def put_authentication_key(
        self,
        object_id: int,
        label: AnyString,
        domains: Set[int],
        capabilities: Set[constants.Capability],
        algorithm: constants.Algorithm,
        delegated_capabilities: Set[constants.Capability],
        encryption_key: ByteString,
        mac_key: ByteString,
    ) -> messages.PutAuthenticationKeyResponse:
        msg = messages.PutAuthenticationKeyRequest(
            object_id,
            encode_label(label),
            encode_domains(domains),
            encode_capabilities(capabilities),
            algorithm,
            encode_capabilities(delegated_capabilities),
            encryption_key,
            mac_key,
        )
        return await self.query(msg, messages.PutAuthenticationKeyResponse)

    async def put_authentication_key_password(
        self,
        object_id: int,
        label: AnyString,
        domains: Set[int],
        capabilities: Set[constants.Capability],
        algorithm: constants.Algorithm,
        delegated_capabilities: Set[constants.Capability],
        password: AnyStr,
    ) -> messages.PutAuthenticationKeyResponse:
        return await self.put_authentication_key(
            object_id,
            label,
            domains,
            capabilities,
            algorithm,
            delegated_capabilities,
            *crypto.derive_password(password),
        )
