from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class AesNistTest(_message.Message):
    __slots__ = ["id", "count", "key", "plaintext", "ciphertext", "iv", "aad", "tag", "is_valid", "encrypt", "line_number"]
    ID_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    PLAINTEXT_FIELD_NUMBER: _ClassVar[int]
    CIPHERTEXT_FIELD_NUMBER: _ClassVar[int]
    IV_FIELD_NUMBER: _ClassVar[int]
    AAD_FIELD_NUMBER: _ClassVar[int]
    TAG_FIELD_NUMBER: _ClassVar[int]
    IS_VALID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPT_FIELD_NUMBER: _ClassVar[int]
    LINE_NUMBER_FIELD_NUMBER: _ClassVar[int]
    id: int
    count: int
    key: str
    plaintext: str
    ciphertext: str
    iv: str
    aad: str
    tag: str
    is_valid: bool
    encrypt: bool
    line_number: int
    def __init__(self, id: _Optional[int] = ..., count: _Optional[int] = ..., key: _Optional[str] = ..., plaintext: _Optional[str] = ..., ciphertext: _Optional[str] = ..., iv: _Optional[str] = ..., aad: _Optional[str] = ..., tag: _Optional[str] = ..., is_valid: bool = ..., encrypt: bool = ..., line_number: _Optional[int] = ...) -> None: ...

class AesNistVectors(_message.Message):
    __slots__ = ["name", "tests", "mode", "key_length"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    TESTS_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    KEY_LENGTH_FIELD_NUMBER: _ClassVar[int]
    name: str
    tests: _containers.RepeatedCompositeFieldContainer[AesNistTest]
    mode: str
    key_length: int
    def __init__(self, name: _Optional[str] = ..., tests: _Optional[_Iterable[_Union[AesNistTest, _Mapping]]] = ..., mode: _Optional[str] = ..., key_length: _Optional[int] = ...) -> None: ...
