from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class KyberNistTest(_message.Message):
    __slots__ = ("count", "seed", "pk", "sk", "ct", "ss")
    COUNT_FIELD_NUMBER: _ClassVar[int]
    SEED_FIELD_NUMBER: _ClassVar[int]
    PK_FIELD_NUMBER: _ClassVar[int]
    SK_FIELD_NUMBER: _ClassVar[int]
    CT_FIELD_NUMBER: _ClassVar[int]
    SS_FIELD_NUMBER: _ClassVar[int]
    count: int
    seed: bytes
    pk: bytes
    sk: bytes
    ct: bytes
    ss: bytes
    def __init__(self, count: _Optional[int] = ..., seed: _Optional[bytes] = ..., pk: _Optional[bytes] = ..., sk: _Optional[bytes] = ..., ct: _Optional[bytes] = ..., ss: _Optional[bytes] = ...) -> None: ...

class KyberNistVectors(_message.Message):
    __slots__ = ("name", "tests")
    NAME_FIELD_NUMBER: _ClassVar[int]
    TESTS_FIELD_NUMBER: _ClassVar[int]
    name: str
    tests: _containers.RepeatedCompositeFieldContainer[KyberNistTest]
    def __init__(self, name: _Optional[str] = ..., tests: _Optional[_Iterable[_Union[KyberNistTest, _Mapping]]] = ...) -> None: ...
