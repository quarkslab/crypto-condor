from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class DilithiumNistTest(_message.Message):
    __slots__ = ("count", "seed", "mlen", "msg", "pk", "sk", "smlen", "sm")
    COUNT_FIELD_NUMBER: _ClassVar[int]
    SEED_FIELD_NUMBER: _ClassVar[int]
    MLEN_FIELD_NUMBER: _ClassVar[int]
    MSG_FIELD_NUMBER: _ClassVar[int]
    PK_FIELD_NUMBER: _ClassVar[int]
    SK_FIELD_NUMBER: _ClassVar[int]
    SMLEN_FIELD_NUMBER: _ClassVar[int]
    SM_FIELD_NUMBER: _ClassVar[int]
    count: int
    seed: bytes
    mlen: int
    msg: bytes
    pk: bytes
    sk: bytes
    smlen: int
    sm: bytes
    def __init__(self, count: _Optional[int] = ..., seed: _Optional[bytes] = ..., mlen: _Optional[int] = ..., msg: _Optional[bytes] = ..., pk: _Optional[bytes] = ..., sk: _Optional[bytes] = ..., smlen: _Optional[int] = ..., sm: _Optional[bytes] = ...) -> None: ...

class DilithiumNistVectors(_message.Message):
    __slots__ = ("name", "tests")
    NAME_FIELD_NUMBER: _ClassVar[int]
    TESTS_FIELD_NUMBER: _ClassVar[int]
    name: str
    tests: _containers.RepeatedCompositeFieldContainer[DilithiumNistTest]
    def __init__(self, name: _Optional[str] = ..., tests: _Optional[_Iterable[_Union[DilithiumNistTest, _Mapping]]] = ...) -> None: ...
