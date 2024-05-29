from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class RsaNistSigGenTest(_message.Message):
    __slots__ = ["alg", "msg", "sig", "line_number"]
    ALG_FIELD_NUMBER: _ClassVar[int]
    MSG_FIELD_NUMBER: _ClassVar[int]
    SIG_FIELD_NUMBER: _ClassVar[int]
    LINE_NUMBER_FIELD_NUMBER: _ClassVar[int]
    alg: str
    msg: str
    sig: str
    line_number: int
    def __init__(self, alg: _Optional[str] = ..., msg: _Optional[str] = ..., sig: _Optional[str] = ..., line_number: _Optional[int] = ...) -> None: ...

class RsaNistSigGenVectors(_message.Message):
    __slots__ = ["filename", "mod", "n", "e", "d", "tests"]
    FILENAME_FIELD_NUMBER: _ClassVar[int]
    MOD_FIELD_NUMBER: _ClassVar[int]
    N_FIELD_NUMBER: _ClassVar[int]
    E_FIELD_NUMBER: _ClassVar[int]
    D_FIELD_NUMBER: _ClassVar[int]
    TESTS_FIELD_NUMBER: _ClassVar[int]
    filename: str
    mod: int
    n: str
    e: str
    d: str
    tests: _containers.RepeatedCompositeFieldContainer[RsaNistSigGenTest]
    def __init__(self, filename: _Optional[str] = ..., mod: _Optional[int] = ..., n: _Optional[str] = ..., e: _Optional[str] = ..., d: _Optional[str] = ..., tests: _Optional[_Iterable[_Union[RsaNistSigGenTest, _Mapping]]] = ...) -> None: ...

class RsaNistSigVerTest(_message.Message):
    __slots__ = ["e", "d", "msg", "sig", "salt", "result", "reason"]
    E_FIELD_NUMBER: _ClassVar[int]
    D_FIELD_NUMBER: _ClassVar[int]
    MSG_FIELD_NUMBER: _ClassVar[int]
    SIG_FIELD_NUMBER: _ClassVar[int]
    SALT_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    e: str
    d: str
    msg: str
    sig: str
    salt: str
    result: bool
    reason: str
    def __init__(self, e: _Optional[str] = ..., d: _Optional[str] = ..., msg: _Optional[str] = ..., sig: _Optional[str] = ..., salt: _Optional[str] = ..., result: bool = ..., reason: _Optional[str] = ...) -> None: ...

class RsaNistSigVerVectors(_message.Message):
    __slots__ = ["id", "mod", "n", "p", "q", "sha", "tests"]
    ID_FIELD_NUMBER: _ClassVar[int]
    MOD_FIELD_NUMBER: _ClassVar[int]
    N_FIELD_NUMBER: _ClassVar[int]
    P_FIELD_NUMBER: _ClassVar[int]
    Q_FIELD_NUMBER: _ClassVar[int]
    SHA_FIELD_NUMBER: _ClassVar[int]
    TESTS_FIELD_NUMBER: _ClassVar[int]
    id: int
    mod: int
    n: str
    p: str
    q: str
    sha: str
    tests: _containers.RepeatedCompositeFieldContainer[RsaNistSigVerTest]
    def __init__(self, id: _Optional[int] = ..., mod: _Optional[int] = ..., n: _Optional[str] = ..., p: _Optional[str] = ..., q: _Optional[str] = ..., sha: _Optional[str] = ..., tests: _Optional[_Iterable[_Union[RsaNistSigVerTest, _Mapping]]] = ...) -> None: ...
