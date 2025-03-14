"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""

import builtins
import collections.abc
import google.protobuf.descriptor
import google.protobuf.internal.containers
import google.protobuf.message
import typing

DESCRIPTOR: google.protobuf.descriptor.FileDescriptor

@typing.final
class ShakeTest(google.protobuf.message.Message):
    """A single SHAKE test vector."""

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    ID_FIELD_NUMBER: builtins.int
    TYPE_FIELD_NUMBER: builtins.int
    COMMENT_FIELD_NUMBER: builtins.int
    FLAGS_FIELD_NUMBER: builtins.int
    MSG_FIELD_NUMBER: builtins.int
    OUT_FIELD_NUMBER: builtins.int
    id: builtins.int
    """The test ID, unique in its set of vectors."""
    type: builtins.str
    """The type of test. One of: valid, invalid, acceptable."""
    comment: builtins.str
    """A comment on the test."""
    msg: builtins.bytes
    """The input message."""
    out: builtins.bytes
    """The resulting digest."""
    @property
    def flags(self) -> google.protobuf.internal.containers.RepeatedScalarFieldContainer[builtins.str]:
        """Flags that categorize this test."""

    def __init__(
        self,
        *,
        id: builtins.int = ...,
        type: builtins.str = ...,
        comment: builtins.str = ...,
        flags: collections.abc.Iterable[builtins.str] | None = ...,
        msg: builtins.bytes = ...,
        out: builtins.bytes = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing.Literal["comment", b"comment", "flags", b"flags", "id", b"id", "msg", b"msg", "out", b"out", "type", b"type"]) -> None: ...

global___ShakeTest = ShakeTest

@typing.final
class ShakeMcTest(google.protobuf.message.Message):
    """A Monte-Carlo test -- refer to SHA3VS from CAVP for usage instructions."""

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    @typing.final
    class CheckpointsEntry(google.protobuf.message.Message):
        DESCRIPTOR: google.protobuf.descriptor.Descriptor

        KEY_FIELD_NUMBER: builtins.int
        VALUE_FIELD_NUMBER: builtins.int
        key: builtins.int
        value: builtins.bytes
        def __init__(
            self,
            *,
            key: builtins.int = ...,
            value: builtins.bytes = ...,
        ) -> None: ...
        def ClearField(self, field_name: typing.Literal["key", b"key", "value", b"value"]) -> None: ...

    ID_FIELD_NUMBER: builtins.int
    TYPE_FIELD_NUMBER: builtins.int
    COMMENT_FIELD_NUMBER: builtins.int
    FLAGS_FIELD_NUMBER: builtins.int
    SEED_FIELD_NUMBER: builtins.int
    CHECKPOINTS_FIELD_NUMBER: builtins.int
    MIN_LEN_FIELD_NUMBER: builtins.int
    MAX_LEN_FIELD_NUMBER: builtins.int
    id: builtins.int
    """The test ID, unique in its set of vectors."""
    type: builtins.str
    """The type of test. One of: valid, invalid, acceptable."""
    comment: builtins.str
    """A comment on the test."""
    seed: builtins.bytes
    """The initial message."""
    min_len: builtins.int
    """The minimum length that is tested, in bits."""
    max_len: builtins.int
    """The maximum length that is tested, in bits."""
    @property
    def flags(self) -> google.protobuf.internal.containers.RepeatedScalarFieldContainer[builtins.str]:
        """Flags that categorize this test."""

    @property
    def checkpoints(self) -> google.protobuf.internal.containers.ScalarMap[builtins.int, builtins.bytes]:
        """A dictionary of checkpoints: the indexes are the keys, the checkpoints
        are the values.
        """

    def __init__(
        self,
        *,
        id: builtins.int = ...,
        type: builtins.str = ...,
        comment: builtins.str = ...,
        flags: collections.abc.Iterable[builtins.str] | None = ...,
        seed: builtins.bytes = ...,
        checkpoints: collections.abc.Mapping[builtins.int, builtins.bytes] | None = ...,
        min_len: builtins.int = ...,
        max_len: builtins.int = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing.Literal["checkpoints", b"checkpoints", "comment", b"comment", "flags", b"flags", "id", b"id", "max_len", b"max_len", "min_len", b"min_len", "seed", b"seed", "type", b"type"]) -> None: ...

global___ShakeMcTest = ShakeMcTest

@typing.final
class ShakeVectors(google.protobuf.message.Message):
    """A set of SHAKE test vectors."""

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    @typing.final
    class NotesEntry(google.protobuf.message.Message):
        DESCRIPTOR: google.protobuf.descriptor.Descriptor

        KEY_FIELD_NUMBER: builtins.int
        VALUE_FIELD_NUMBER: builtins.int
        key: builtins.str
        value: builtins.str
        def __init__(
            self,
            *,
            key: builtins.str = ...,
            value: builtins.str = ...,
        ) -> None: ...
        def ClearField(self, field_name: typing.Literal["key", b"key", "value", b"value"]) -> None: ...

    SOURCE_FIELD_NUMBER: builtins.int
    SOURCE_DESC_FIELD_NUMBER: builtins.int
    SOURCE_URL_FIELD_NUMBER: builtins.int
    COMPLIANCE_FIELD_NUMBER: builtins.int
    NOTES_FIELD_NUMBER: builtins.int
    TESTS_FIELD_NUMBER: builtins.int
    MC_TEST_FIELD_NUMBER: builtins.int
    ALGORITHM_FIELD_NUMBER: builtins.int
    ORIENTATION_FIELD_NUMBER: builtins.int
    source: builtins.str
    """The source of the test vectors."""
    source_desc: builtins.str
    """Description of the source."""
    source_url: builtins.str
    """The URL of the source."""
    compliance: builtins.bool
    """Whether these are compliance test vectors or not."""
    algorithm: builtins.str
    """The SHAKE variant."""
    orientation: builtins.str
    """The orientation of the implementation: bit- or byte-oriented."""
    @property
    def notes(self) -> google.protobuf.internal.containers.ScalarMap[builtins.str, builtins.str]:
        """A dictionary of test flags and their description."""

    @property
    def tests(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___ShakeTest]:
        """The test vectors."""

    @property
    def mc_test(self) -> global___ShakeMcTest:
        """The Monte-Carlo test. This field is used for NIST CAVP tests and is not required.
        Users of this class are expected to check the presence of this field.
        """

    def __init__(
        self,
        *,
        source: builtins.str = ...,
        source_desc: builtins.str = ...,
        source_url: builtins.str = ...,
        compliance: builtins.bool = ...,
        notes: collections.abc.Mapping[builtins.str, builtins.str] | None = ...,
        tests: collections.abc.Iterable[global___ShakeTest] | None = ...,
        mc_test: global___ShakeMcTest | None = ...,
        algorithm: builtins.str = ...,
        orientation: builtins.str = ...,
    ) -> None: ...
    def HasField(self, field_name: typing.Literal["mc_test", b"mc_test"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing.Literal["algorithm", b"algorithm", "compliance", b"compliance", "mc_test", b"mc_test", "notes", b"notes", "orientation", b"orientation", "source", b"source", "source_desc", b"source_desc", "source_url", b"source_url", "tests", b"tests"]) -> None: ...

global___ShakeVectors = ShakeVectors
