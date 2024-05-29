from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class EcdsaNistSigVerTest(_message.Message):
    __slots__ = ["id", "message", "qx", "qy", "r", "s", "result", "fail_reason", "line_number"]
    ID_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    QX_FIELD_NUMBER: _ClassVar[int]
    QY_FIELD_NUMBER: _ClassVar[int]
    R_FIELD_NUMBER: _ClassVar[int]
    S_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    FAIL_REASON_FIELD_NUMBER: _ClassVar[int]
    LINE_NUMBER_FIELD_NUMBER: _ClassVar[int]
    id: int
    message: str
    qx: str
    qy: str
    r: str
    s: str
    result: str
    fail_reason: str
    line_number: int
    def __init__(self, id: _Optional[int] = ..., message: _Optional[str] = ..., qx: _Optional[str] = ..., qy: _Optional[str] = ..., r: _Optional[str] = ..., s: _Optional[str] = ..., result: _Optional[str] = ..., fail_reason: _Optional[str] = ..., line_number: _Optional[int] = ...) -> None: ...

class EcdsaNistSigVerVectors(_message.Message):
    __slots__ = ["name", "curve", "hash_algo", "tests"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    CURVE_FIELD_NUMBER: _ClassVar[int]
    HASH_ALGO_FIELD_NUMBER: _ClassVar[int]
    TESTS_FIELD_NUMBER: _ClassVar[int]
    name: str
    curve: str
    hash_algo: str
    tests: _containers.RepeatedCompositeFieldContainer[EcdsaNistSigVerTest]
    def __init__(self, name: _Optional[str] = ..., curve: _Optional[str] = ..., hash_algo: _Optional[str] = ..., tests: _Optional[_Iterable[_Union[EcdsaNistSigVerTest, _Mapping]]] = ...) -> None: ...

class EcdsaNistSigGenTest(_message.Message):
    __slots__ = ["id", "message", "d", "qx", "qy", "k", "r", "s", "line_number"]
    ID_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    D_FIELD_NUMBER: _ClassVar[int]
    QX_FIELD_NUMBER: _ClassVar[int]
    QY_FIELD_NUMBER: _ClassVar[int]
    K_FIELD_NUMBER: _ClassVar[int]
    R_FIELD_NUMBER: _ClassVar[int]
    S_FIELD_NUMBER: _ClassVar[int]
    LINE_NUMBER_FIELD_NUMBER: _ClassVar[int]
    id: int
    message: str
    d: str
    qx: str
    qy: str
    k: str
    r: str
    s: str
    line_number: int
    def __init__(self, id: _Optional[int] = ..., message: _Optional[str] = ..., d: _Optional[str] = ..., qx: _Optional[str] = ..., qy: _Optional[str] = ..., k: _Optional[str] = ..., r: _Optional[str] = ..., s: _Optional[str] = ..., line_number: _Optional[int] = ...) -> None: ...

class EcdsaNistSigGenVectors(_message.Message):
    __slots__ = ["name", "curve", "hash_algo", "tests"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    CURVE_FIELD_NUMBER: _ClassVar[int]
    HASH_ALGO_FIELD_NUMBER: _ClassVar[int]
    TESTS_FIELD_NUMBER: _ClassVar[int]
    name: str
    curve: str
    hash_algo: str
    tests: _containers.RepeatedCompositeFieldContainer[EcdsaNistSigGenTest]
    def __init__(self, name: _Optional[str] = ..., curve: _Optional[str] = ..., hash_algo: _Optional[str] = ..., tests: _Optional[_Iterable[_Union[EcdsaNistSigGenTest, _Mapping]]] = ...) -> None: ...
