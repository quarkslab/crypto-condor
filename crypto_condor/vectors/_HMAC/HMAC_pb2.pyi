from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class HmacNistTest(_message.Message):
    __slots__ = ("count", "klen", "tlen", "key", "msg", "mac", "line_number")
    COUNT_FIELD_NUMBER: _ClassVar[int]
    KLEN_FIELD_NUMBER: _ClassVar[int]
    TLEN_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    MSG_FIELD_NUMBER: _ClassVar[int]
    MAC_FIELD_NUMBER: _ClassVar[int]
    LINE_NUMBER_FIELD_NUMBER: _ClassVar[int]
    count: int
    klen: int
    tlen: int
    key: bytes
    msg: bytes
    mac: bytes
    line_number: int
    def __init__(self, count: _Optional[int] = ..., klen: _Optional[int] = ..., tlen: _Optional[int] = ..., key: _Optional[bytes] = ..., msg: _Optional[bytes] = ..., mac: _Optional[bytes] = ..., line_number: _Optional[int] = ...) -> None: ...

class HmacNistVectors(_message.Message):
    __slots__ = ("filename", "hashname", "tests")
    FILENAME_FIELD_NUMBER: _ClassVar[int]
    HASHNAME_FIELD_NUMBER: _ClassVar[int]
    TESTS_FIELD_NUMBER: _ClassVar[int]
    filename: str
    hashname: str
    tests: _containers.RepeatedCompositeFieldContainer[HmacNistTest]
    def __init__(self, filename: _Optional[str] = ..., hashname: _Optional[str] = ..., tests: _Optional[_Iterable[_Union[HmacNistTest, _Mapping]]] = ...) -> None: ...

class HmacWycheproofTest(_message.Message):
    __slots__ = ("count", "comment", "key", "msg", "mac", "result", "flags")
    COUNT_FIELD_NUMBER: _ClassVar[int]
    COMMENT_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    MSG_FIELD_NUMBER: _ClassVar[int]
    MAC_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    count: int
    comment: str
    key: bytes
    msg: bytes
    mac: bytes
    result: str
    flags: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, count: _Optional[int] = ..., comment: _Optional[str] = ..., key: _Optional[bytes] = ..., msg: _Optional[bytes] = ..., mac: _Optional[bytes] = ..., result: _Optional[str] = ..., flags: _Optional[_Iterable[str]] = ...) -> None: ...

class HmacWycheproofGroup(_message.Message):
    __slots__ = ("key_size", "tag_size", "tests")
    KEY_SIZE_FIELD_NUMBER: _ClassVar[int]
    TAG_SIZE_FIELD_NUMBER: _ClassVar[int]
    TESTS_FIELD_NUMBER: _ClassVar[int]
    key_size: int
    tag_size: int
    tests: _containers.RepeatedCompositeFieldContainer[HmacWycheproofTest]
    def __init__(self, key_size: _Optional[int] = ..., tag_size: _Optional[int] = ..., tests: _Optional[_Iterable[_Union[HmacWycheproofTest, _Mapping]]] = ...) -> None: ...

class HmacWycheproofVectors(_message.Message):
    __slots__ = ("filename", "algorithm", "version", "header", "number_of_tests", "notes", "groups")
    class NotesEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    FILENAME_FIELD_NUMBER: _ClassVar[int]
    ALGORITHM_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    HEADER_FIELD_NUMBER: _ClassVar[int]
    NUMBER_OF_TESTS_FIELD_NUMBER: _ClassVar[int]
    NOTES_FIELD_NUMBER: _ClassVar[int]
    GROUPS_FIELD_NUMBER: _ClassVar[int]
    filename: str
    algorithm: str
    version: str
    header: _containers.RepeatedScalarFieldContainer[str]
    number_of_tests: int
    notes: _containers.ScalarMap[str, str]
    groups: _containers.RepeatedCompositeFieldContainer[HmacWycheproofGroup]
    def __init__(self, filename: _Optional[str] = ..., algorithm: _Optional[str] = ..., version: _Optional[str] = ..., header: _Optional[_Iterable[str]] = ..., number_of_tests: _Optional[int] = ..., notes: _Optional[_Mapping[str, str]] = ..., groups: _Optional[_Iterable[_Union[HmacWycheproofGroup, _Mapping]]] = ...) -> None: ...
