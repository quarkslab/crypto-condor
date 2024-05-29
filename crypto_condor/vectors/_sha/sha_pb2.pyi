from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ShaNistTest(_message.Message):
    __slots__ = ["len", "msg", "md", "line_number"]
    LEN_FIELD_NUMBER: _ClassVar[int]
    MSG_FIELD_NUMBER: _ClassVar[int]
    MD_FIELD_NUMBER: _ClassVar[int]
    LINE_NUMBER_FIELD_NUMBER: _ClassVar[int]
    len: int
    msg: str
    md: str
    line_number: int
    def __init__(self, len: _Optional[int] = ..., msg: _Optional[str] = ..., md: _Optional[str] = ..., line_number: _Optional[int] = ...) -> None: ...

class ShaNistVectors(_message.Message):
    __slots__ = ["filename", "tests"]
    FILENAME_FIELD_NUMBER: _ClassVar[int]
    TESTS_FIELD_NUMBER: _ClassVar[int]
    filename: str
    tests: _containers.RepeatedCompositeFieldContainer[ShaNistTest]
    def __init__(self, filename: _Optional[str] = ..., tests: _Optional[_Iterable[_Union[ShaNistTest, _Mapping]]] = ...) -> None: ...

class ShaMonteCarloNistVectors(_message.Message):
    __slots__ = ["filename", "seed", "tests"]
    class TestsEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: int
        value: str
        def __init__(self, key: _Optional[int] = ..., value: _Optional[str] = ...) -> None: ...
    FILENAME_FIELD_NUMBER: _ClassVar[int]
    SEED_FIELD_NUMBER: _ClassVar[int]
    TESTS_FIELD_NUMBER: _ClassVar[int]
    filename: str
    seed: str
    tests: _containers.ScalarMap[int, str]
    def __init__(self, filename: _Optional[str] = ..., seed: _Optional[str] = ..., tests: _Optional[_Mapping[int, str]] = ...) -> None: ...

class ShakeNistTest(_message.Message):
    __slots__ = ["len", "msg", "output", "line_number"]
    LEN_FIELD_NUMBER: _ClassVar[int]
    MSG_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    LINE_NUMBER_FIELD_NUMBER: _ClassVar[int]
    len: int
    msg: str
    output: str
    line_number: int
    def __init__(self, len: _Optional[int] = ..., msg: _Optional[str] = ..., output: _Optional[str] = ..., line_number: _Optional[int] = ...) -> None: ...

class ShakeNistVectors(_message.Message):
    __slots__ = ["filename", "output_len", "tests"]
    FILENAME_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_LEN_FIELD_NUMBER: _ClassVar[int]
    TESTS_FIELD_NUMBER: _ClassVar[int]
    filename: str
    output_len: int
    tests: _containers.RepeatedCompositeFieldContainer[ShakeNistTest]
    def __init__(self, filename: _Optional[str] = ..., output_len: _Optional[int] = ..., tests: _Optional[_Iterable[_Union[ShakeNistTest, _Mapping]]] = ...) -> None: ...

class ShakeMonteNistVectors(_message.Message):
    __slots__ = ["filename", "msg", "max_len", "min_len", "tests"]
    class TestsEntry(_message.Message):
        __slots__ = ["key", "value"]
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: int
        value: str
        def __init__(self, key: _Optional[int] = ..., value: _Optional[str] = ...) -> None: ...
    FILENAME_FIELD_NUMBER: _ClassVar[int]
    MSG_FIELD_NUMBER: _ClassVar[int]
    MAX_LEN_FIELD_NUMBER: _ClassVar[int]
    MIN_LEN_FIELD_NUMBER: _ClassVar[int]
    TESTS_FIELD_NUMBER: _ClassVar[int]
    filename: str
    msg: str
    max_len: int
    min_len: int
    tests: _containers.ScalarMap[int, str]
    def __init__(self, filename: _Optional[str] = ..., msg: _Optional[str] = ..., max_len: _Optional[int] = ..., min_len: _Optional[int] = ..., tests: _Optional[_Mapping[int, str]] = ...) -> None: ...

class ShakeVariableNistTest(_message.Message):
    __slots__ = ["count", "output_len", "msg", "output", "line_number"]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_LEN_FIELD_NUMBER: _ClassVar[int]
    MSG_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    LINE_NUMBER_FIELD_NUMBER: _ClassVar[int]
    count: int
    output_len: int
    msg: str
    output: str
    line_number: int
    def __init__(self, count: _Optional[int] = ..., output_len: _Optional[int] = ..., msg: _Optional[str] = ..., output: _Optional[str] = ..., line_number: _Optional[int] = ...) -> None: ...

class ShakeVariableNistVectors(_message.Message):
    __slots__ = ["filename", "tests"]
    FILENAME_FIELD_NUMBER: _ClassVar[int]
    TESTS_FIELD_NUMBER: _ClassVar[int]
    filename: str
    tests: _containers.RepeatedCompositeFieldContainer[ShakeVariableNistTest]
    def __init__(self, filename: _Optional[str] = ..., tests: _Optional[_Iterable[_Union[ShakeVariableNistTest, _Mapping]]] = ...) -> None: ...
