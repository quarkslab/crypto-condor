from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class SphincsNistKatTest(_message.Message):
    __slots__ = ["count", "seed", "mlen", "msg", "pk", "sk", "smlen", "sm", "line_number"]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    SEED_FIELD_NUMBER: _ClassVar[int]
    MLEN_FIELD_NUMBER: _ClassVar[int]
    MSG_FIELD_NUMBER: _ClassVar[int]
    PK_FIELD_NUMBER: _ClassVar[int]
    SK_FIELD_NUMBER: _ClassVar[int]
    SMLEN_FIELD_NUMBER: _ClassVar[int]
    SM_FIELD_NUMBER: _ClassVar[int]
    LINE_NUMBER_FIELD_NUMBER: _ClassVar[int]
    count: int
    seed: str
    mlen: int
    msg: str
    pk: str
    sk: str
    smlen: int
    sm: str
    line_number: int
    def __init__(self, count: _Optional[int] = ..., seed: _Optional[str] = ..., mlen: _Optional[int] = ..., msg: _Optional[str] = ..., pk: _Optional[str] = ..., sk: _Optional[str] = ..., smlen: _Optional[int] = ..., sm: _Optional[str] = ..., line_number: _Optional[int] = ...) -> None: ...

class SphincsNistKatVectors(_message.Message):
    __slots__ = ["name", "tests"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    TESTS_FIELD_NUMBER: _ClassVar[int]
    name: str
    tests: _containers.RepeatedCompositeFieldContainer[SphincsNistKatTest]
    def __init__(self, name: _Optional[str] = ..., tests: _Optional[_Iterable[_Union[SphincsNistKatTest, _Mapping]]] = ...) -> None: ...
