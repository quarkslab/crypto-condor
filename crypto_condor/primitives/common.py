"""Module for common objects.

This module provides the :class:`Results` class to record test results in an uniform
manner. These can be grouped with the :class:`ResultsDict` class.

To have a common set of attributes each individual test should have, the
:class:`DebugInfo` and the new :class:`TestInfo` classes should be used. One of such
attributes is the type of test vector, which is defined by the :enum:`TestType` enum.

For functions that have to persist application data, the :func:`get_appdata_dir`
function returns the path to use.
"""

import collections
import datetime
import importlib
import logging
import os
import sys
from pathlib import Path
from typing import Any, TypeAlias

import attrs
import strenum
from rich.console import Console as RichConsole
from rich.panel import Panel
from rich.progress import track
from rich.prompt import Confirm, Prompt

# --------------------------- Module --------------------------------------------------

logger = logging.getLogger(__name__)


def __dir__():  # pragma: no cover
    return [
        # Type aliases
        "CiphertextAndTag",
        "PlaintextAndBool",
        # Enums
        TestType.__name__,
        # Results
        DebugInfo.__name__,
        Results.__name__,
        ResultsDict.__name__,
        TestInfo.__name__,
        # Console
        Console.__name__,
        # Functions
        get_appdata_dir.__name__,
    ]


# --------------------------- Type aliases --------------------------------------------

CiphertextAndTag: TypeAlias = tuple[bytes, bytes]
"""The return type for encrypting with authenticated modes of operation.

The encryption function returns the ciphertext along with an authentication tag that
must be used by the decryption function to ensure that the ciphertext hasn't been
tampered with.
"""

# The rationale of using a boolean instead of raising an error when the tag verification
# fails (like pycryptodome does for example) was to avoid the cost of catching an
# exception when testing thousands of test vectors. It also means that wrapper users are
# only concerned with returning values and not raising exceptions. This does not mean
# that the test functions shouldn't catch exceptions at all, but we expect that most are
# due to other circumstances.
PlaintextAndBool: TypeAlias = tuple[bytes | None, bool]
"""The return type for decrypting with authenticated modes of operation.

The decryption function takes the ciphertext and tag as input, tries to decrypt the
ciphertext, and validates the resulting plaintext using the tag. If the verification
succeeds, return (plaintext, True).  Otherwise, the plaintext should not be released so
return (None, False).
"""

# --------------------------- Enums ---------------------------------------------------


class TestType(strenum.StrEnum):
    """The different types of test vectors.

    Test vectors can be separated into three types:

    - :attr:`VALID` tests represent the expected behaviour when dealing with correct
      inputs. For example, signing a message with ECDSA using a *valid* private key for
      the given elliptic curve.
    - :attr:`INVALID` tests use invalid inputs and the implementation is expected to
      to reject them or fail in some way. For example, when verifying signatures ECDSA,
      implementations are expected to reject a signature if it is equal to (0, 0).
    - :attr:`ACCEPTABLE` tests are inputs resulting from legacy implementations or weak
      parameters. Passing these tests is acceptable but failing them is expected, and
      thus not an actual failure.
    """

    VALID = "valid"
    INVALID = "invalid"
    ACCEPTABLE = "acceptable"


# --------------------------- Results -------------------------------------------------

_DEFAULT_NOTES = {
    "Compliance": (
        "Test vectors provided in the specification to test the"
        " correctness of an implementation."
    ),
    "Compliance/EmptyPlaintext": "Test vector with an empty plaintext.",
    "Compliance/EmptyCiphertext": "Test vector with an empty ciphertext.",
    "Resilience/EmptyPlaintext": "Test vector with an empty plaintext.",
    "Resilience/EmptyCiphertext": "Test vector with an empty ciphertext.",
    "NoFlag": "Test vector without flag.",
    "UserInput": "User-provided·vectors.",
    "RandomTest": "Test values are randomly generated.",
}
"""Dictionary of commonly used flags and their notes."""


def _default_notes() -> dict[str, str]:
    """Returns a dictionary of commonly used flags and their note."""
    return dict(_DEFAULT_NOTES)


@attrs.define
class DebugInfo:
    r"""Information about a single test.

    Note: for new primitives, prefer to use :class:`TestInfo`.

    Each test is expected to have some common information such as its ID or
    :class:`TestType`. This class provides a common interface for this information.

    Debug data classes in primitive modules are expected to have an instance of this
    class as their (first) argument called ``info``. They can then define data specific
    to that test as the other arguments.

    This class has a custom :meth:`__str__` method to provide a string representation
    for user display. Classes using DebugInfo should use it to display all the
    information available.

    Args:
        tid: A unique ID used to identify the test and its result. Uniqueness should be
            enforced by the parent :class:`Results`.
        test_type: The type of test, refer to :enum:`TestType`.
        flags: A list of flags that categorise the test.
        result: Whether the operation was successful or not.
        comment: An optional comment about the test, usually explaining what the input
            values are testing. For example in AES-GCM "IV length different than 96
            bits".
        error_msg: An error message in case of operation failure. Usually the message of
            the exception caught or a message indicating what part of the operation
            failed (e.g. "MAC tag is invalid" in AEAD modes).

    Example:
        >>> from crypto_condor.primitives.common import DebugInfo
        >>> import attrs

        >>> @attrs.define
        ... class MyDebugData:
        ...     info: DebugInfo
        ...     key: bytes
        ...     message: bytes
        ...     signature: bytes
        ...     def __str__(self):
        ...         s = str(self.info)
        ...         s += f"key = {self.key.hex()}\n"
        ...         s += f"message = {self.message.hex()}\n"
        ...         s += f"signature = {self.signature.hex()}\n"
        ...         return s
    """

    tid: int
    test_type: TestType
    flags: list[str]
    result: bool = False
    comment: str | None = None
    error_msg: str | None = None

    def __str__(self):
        """Returns a string representation."""
        s = f"ID = {self.tid}\n"
        s += f"Result = {'PASS' if self.result else 'FAIL'}\n"
        # TODO: add test type?
        # s += f"Test type: {self.test_type}\n"
        s += f"Flags: {self.flags}\n"
        s += f"Comment = {self.comment if self.comment else '<none>'}\n"
        if self.error_msg:
            s += f"Error = {self.error_msg}\n"
        return s


@attrs.define
class TestInfo:
    """Information about a single test.

    This data class defines the set of common attributes each test result should have,
    such as an ID and the type of test vector used.

    Do not instantiate directly: to create a new instance use :meth:`new`. After calling
    the implementation, use :meth:`ok` or :meth:`fail`.

    Args:
        id: A numerical ID for this test. Should be unique among tests of the same
            :class:`Results` instance. Uniqueness is enforced by the latter.
        type: The type of test vector used.
        flags: Tags that categorise test vectors.
        result: Whether the test passed or failed. None means that the value has not
            been explicitly set yet.
        comment: An optional description of what the test vector is testing.
        err_msg: A message explaining why the test failed, None if the test passed.
        data: The optional debug data class instance.
    """

    id: int
    type: TestType
    flags: list[str]
    result: bool | None
    comment: str | None
    err_msg: str | None
    data: Any | None

    def __str__(self) -> str:
        """Returns a string representation."""
        s = f"Test ID = {self.id}\n"
        s += f"Type = {self.type}\n"
        s += f"Flags = {self.flags}\n"
        if self.comment:
            s += f"Comment = {self.comment}\n"
        if self.result:
            s += "Result = [green1]PASS[/]\n"
        elif self.result is not None:
            s += "Result = [red1]FAIL[/]\n"
            if self.err_msg:
                s += "Error = {self.err_msg}\n"
        else:
            s += "Result = [yellow1]None[/]\n"
        return s

    @classmethod
    def new(
        cls,
        id: int,
        type: TestType,
        flags: list[str] | None = None,
        comment: str | None = None,
    ):
        """Creates a new instance of TestInfo.

        Args:
            id: The numerical ID of the test.
            type: The type of test vector, see :enum:`TestType`.
            flags: An optional list of flags that categorize the test.
            comment: An optional comment describing what is being tested.

        Returns:
            A new instance of TestInfo with the ``result``, ``err_msg``, and ``data``
            fields set to None.

        Example:
            Let's create a simple test vector and create a new instance of TestInfo
            based on its information.

            >>> from crypto_condor.primitives.common import TestInfo, TestType
            >>> test = {"id": 1, "type": TestType.VALID, "flags": ["User-defined"]}
            >>> # To create an instance with only the essential information.
            >>> info = TestInfo.new(test["id"], test["type"])
            >>> # If all the tests have flags, we can add them easily.
            >>> info = TestInfo.new(test["id"], test["type"], test["flags"])
            >>> # We can also add a comment about the test.
            >>> info = TestInfo.new(test["id"], test["type"], comment="Edge case")
        """
        if flags is None:
            return cls(id, type, list(), None, comment, None, None)
        else:
            return cls(id, type, flags, None, comment, None, None)

    def ok(self, data: Any | None = None) -> None:
        """Marks a test as passed.

        Args:
            data: Optional test debug data to add.
        """
        self.result = True
        self.data = data

    def fail(self, err_msg: str | None = None, data: Any | None = None) -> None:
        """Marks a test as failed.

        Args:
            err_msg: An optional message explaining why the test failed.
            data: Optional test debug data to add.
        """
        self.result = False
        self.err_msg = err_msg
        self.data = data


@attrs.define
class PassedAndFailed:
    """Information about how many tests passed and failed.

    The usual usage is to instantiate the class without passing any arguments, just
    using the default values.

    Args:
        passed: Counter for the number of tests passed.
        failed: Counter for the number of tests failed.
        passed_flags: A dictionary to count flags for passed tests.
        failed_flags: A dictionary to count flags for failed tests.
        passed_index: A set containing the ID of tests that passed.
        failed_index: A set containing the ID of tests that failed.
    """

    passed: int = 0
    failed: int = 0
    passed_flags: dict[str, int] = attrs.field(
        factory=lambda: collections.defaultdict(int)
    )
    failed_flags: dict[str, int] = attrs.field(
        factory=lambda: collections.defaultdict(int)
    )
    passed_index: set[int] = attrs.field(factory=set)
    failed_index: set[int] = attrs.field(factory=set)

    def __bool__(self) -> bool:
        """Returns True if there are any tests, passed or failed."""
        if self.passed == 0 and self.failed == 0:
            return False
        return True

    def add(self, tid: int, result: bool, flags: list[str]) -> None:
        """Adds a new result.

        Args:
            tid: The test's unique ID.
            result: The result of the operation.
            flags: A list of flags that categorise the test.
        """
        if result:
            self.passed += 1
            self.passed_index.add(tid)
            for flag in flags:
                self.passed_flags[flag] += 1
        else:
            self.failed += 1
            self.failed_index.add(tid)
            for flag in flags:
                self.failed_flags[flag] += 1


@attrs.define
class Results:
    """The results of a test.

    Do not instantiate directly, create a new instance with :meth:`new`.

    This class defines the essential information about a test to have a uniform
    interface across primitives. Usually corresponds to a test of a specific set of
    parameters with a single test vectors file.

    The individual test results are recorded by test type (``valid``, ``invalid``, and
    ``acceptable``), and any debug data is stored. To display the results to the user,
    its :meth:`__str__` method is defined to provide a user-friendly representation that
    uses :mod:`rich`'s markup to add colours.

    Args:
        module: The name of the primitive module.
        function: The name of the function used.
        description: A description of the function.
        arguments: The name of the arguments passed to the function and their values.
        valid: A count of valid tests with their results and flags.
        invalid: A count of invalid tests with their results and flags.
        acceptable: A count of acceptable tests with their results and flags.
        notes: Notes explaining the meaning of the flags. Can contain notes of flags
            that are not used by the tests, they will be omitted from the string
            representation. Initialized with common flags.
        data: Information about each individual test, indexed by test ID.
        _flags: A set of all flags observed. This is used to skip notes associated with
            unused flags for the string representation.
        _tids: A set of test IDs, used to ensure the uniqueness of the ID.
    """

    module: str
    function: str
    description: str
    arguments: dict[str, Any]
    valid: PassedAndFailed = attrs.field(factory=PassedAndFailed)
    invalid: PassedAndFailed = attrs.field(factory=PassedAndFailed)
    acceptable: PassedAndFailed = attrs.field(factory=PassedAndFailed)
    notes: dict[str, str] = attrs.field(factory=_default_notes)
    data: dict[int, Any] = attrs.field(factory=dict)
    _flags: set[str] = attrs.field(factory=set)
    _tids: set[int] = attrs.field(factory=set)

    def __str__(self) -> str:
        """Returns a string representation of the results.

        It uses :mod:`rich` markup to add colours, so it should be printed by e.g. a
        rich console.
        """
        s = f"Module: [bold blue]{self.module}[/]\n"
        s += f"Function: [bold blue]{self.function}[/]\n"
        s += f"Description: {self.description}\n"
        if len(self.arguments) > 0:
            s += "Arguments:\n"
            for arg, val in self.arguments.items():
                s += f"  {arg} = [magenta]{val}[/]\n"

        if self.valid:
            s += "Valid tests:\n"

            if self.valid.passed > 0:
                s += f"  Passed: [green1]{self.valid.passed}[/]\n"
            else:
                s += f"  Passed: {self.valid.passed}\n"
            for flag, count in self.valid.passed_flags.items():
                s += f"    {flag}: [green1]{count}[/]\n"

            if self.valid.failed > 0:
                s += f"  Failed: [red1]{self.valid.failed}[/]\n"
            else:
                s += f"  Failed: [green1]{self.valid.failed}[/]\n"
            for flag, count in self.valid.failed_flags.items():
                s += f"    {flag}: [red1]{count}[/]\n"

        if self.invalid:
            s += "Invalid tests:\n"

            if self.invalid.passed > 0:
                s += f"  Passed: [light_green]{self.invalid.passed}[/]\n"
            else:
                s += f"  Passed: {self.invalid.passed}\n"
            for flag, count in self.invalid.passed_flags.items():
                s += f"    {flag}: [light_green]{count}[/]\n"
            if self.invalid.failed > 0:
                s += f"  Failed: [red1]{self.invalid.failed}[/]\n"
            else:
                s += f"  Failed: [light_green]{self.invalid.failed}[/]\n"
            for flag, count in self.invalid.failed_flags.items():
                s += f"    {flag}: [red1]{count}[/]\n"

        if self.acceptable:
            s += "Acceptable tests:\n"
            s += f"  Passed: [yellow1]{self.acceptable.passed}[/]\n"
            for flag, count in self.acceptable.passed_flags.items():
                s += f"    {flag}: [yellow1]{count}[/]\n"
            s += f"  Failed: [yellow1]{self.acceptable.failed}[/]\n"
            for flag, count in self.acceptable.failed_flags.items():
                s += f"    {flag}: [yellow1]{count}[/]\n"

        if self.notes and len(self._flags) > 0:
            s += "Flag notes:\n"
            for flag, note in self.notes.items():
                if flag in self._flags:
                    s += f"  [orange1]{flag}[/]: {note}\n"

        # Remove the leading newline, avoids the extra space inside the panel.
        return s.rstrip("\n")

    @classmethod
    def new(cls, desc: str, arg_names: list[str]):
        """Creates a new instance of Results for the calling function.

        Uses ``sys`` stack frames to determine the calling function's module and name to
        avoid having to manually instantiate those attributes.

        Args:
            desc: The short description of the function, like the first sentence of the
                docstring.
            arg_names: A list of names of arguments of the calling function to include.
                The frame contains all arguments and its values, this allows to select
                which ones should be included in the results. Notably, the argument used
                to pass the implementation should be skipped, as the value is a function
                pointer, which is not relevant to the results.

        Notes:
            There is no reliable way of getting the docstring from the stack frame,
            which is why the description has to be manually provided.

        Example:
            To create a new instance of Results to record the results of testing an
            implementation of AES encryption, we want to record arguments such as the
            mode of operation and key length.

            >>> from crypto_condor.primitives.common import Results
            >>> results = Results.new(
            ...     "Tests an implementation of AES encryption.", ["mode", "key_length"]
            ... )
        """
        frame = sys._getframe(1)
        mod = Path(frame.f_code.co_filename).stem
        func = frame.f_code.co_name
        args = {arg: value for arg, value in frame.f_locals.items() if arg in arg_names}
        return cls(mod, func, desc, args)

    def add(self, data: TestInfo | Any) -> None:
        """Adds a new result from the result data.

        Args:
            data: A test info class. Either an instance of :class:`TestInfo` or a data
                class that has an attribute called ``info`` which is an instance of
                :class:`DebugInfo`.

        Raises:
            ValueError: If the test ID is already used by a recorded result, or if the
                ``result`` attribute of data is None (which is the default for
                :class:`TestInfo`.)
        """
        if isinstance(data, TestInfo):
            if data.id in self._tids:
                raise ValueError("ID %d is already in use" % data.id)
            if data.result is None:
                raise ValueError("The result of test %d is None" % data.id)
            self._tids.add(data.id)
            self._flags |= set(data.flags)
            self.data[data.id] = data.data
            match data.type:
                case TestType.VALID:
                    self.valid.add(data.id, data.result, data.flags)
                case TestType.INVALID:
                    self.invalid.add(data.id, data.result, data.flags)
                case TestType.ACCEPTABLE:
                    self.acceptable.add(data.id, data.result, data.flags)
            return
        info = data.info
        if info.tid in self._tids:
            raise ValueError("ID %d is already in use" % info.tid)
        self._tids.add(info.tid)
        self._flags |= set(info.flags)
        self.data[info.tid] = data
        match info.test_type:
            case TestType.VALID:
                self.valid.add(info.tid, info.result, info.flags)
            case TestType.INVALID:
                self.invalid.add(info.tid, info.result, info.flags)
            case TestType.ACCEPTABLE:
                self.acceptable.add(info.tid, info.result, info.flags)

    def add_notes(self, notes: dict[str, str]):
        """Adds flag notes from a dictionary of notes."""
        self.notes |= notes

    def check(self, *, empty_as_fail: bool = False) -> bool:
        """Checks if the results have passed.

        Keyword Args:
            empty_as_fail: Whether to consider a lack of passed tests as a failure.

        Returns:
            False if there are failed tests (valid or invalid), or if empty_as_fail is
            True and there are no passed tests; True otherwise.

        Notes:
            The existence of failed tests is checked before empty_as_fail.
        """
        if self.valid.failed > 0 or self.invalid.failed > 0:
            return False
        if empty_as_fail and self.valid.passed == 0 and self.invalid.passed == 0:
            return False
        return True


class ResultsDict(dict):
    """A dictionary of Results.

    This class extends the built-in dictionary to group :class:`Results` as values. The
    keys are defined by the calling function. Currently key uniqueness is not enforced,
    the caller is responsible for not overwriting previous results. See :meth:`add` for
    a suggestion.

    It provides the :meth:`check` method to check for failed results over all of its
    values. It also defines a string representation with :meth:`__str__`, similar to
    that of :class:`Results`.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __str__(self) -> str:
        """Returns a summary of the results contained."""
        s = ""

        val_p, val_f, inv_p, inv_f, acc_p, acc_f = 0, 0, 0, 0, 0, 0
        for r in self.values():
            val_p += r.valid.passed
            val_f += r.valid.failed
            inv_p += r.invalid.passed
            inv_f += r.invalid.failed
            acc_p += r.acceptable.passed
            acc_f += r.acceptable.failed
        if val_p + val_f + inv_p + inv_f + acc_p + acc_f == 0:
            s += "No results\n"
        else:
            if val_p + val_f > 0:
                s += "Valid tests:\n"
                if val_p > 0:
                    s += f"  Passed: [green1]{val_p}[/]\n"
                else:
                    s += f"  Passed: {val_p}\n"
                if val_f > 0:
                    s += f"  Failed: [red1]{val_f}[/]\n"
                else:
                    s += f"  Failed: {val_f}\n"
            if inv_p + inv_f > 0:
                s += "Invalid tests:\n"
                if inv_p > 0:
                    s += f"  Passed: [light_green]{inv_p}[/]\n"
                else:
                    s += f"  Passed: {inv_p}\n"
                if inv_f > 0:
                    s += f"  Failed: [red1]{inv_f}[/]\n"
                else:
                    s += f"  Failed: {inv_f}\n"
            if acc_p + acc_f > 0:
                s += "Acceptable tests:\n"
                s += f"  Passed: [yellow1]{acc_p}[/]\n"
                s += f"  Failed: [yellow1]{acc_f}[/]\n"
        # Remove the leading newline, avoids the extra space inside the panel.
        return s.rstrip("\n")

    def add(self, res: Results | None, arg_names: list[str] | None = None) -> None:
        """Adds Results with a deterministic key.

        It generates the dictionary key from the attributes of the given Results as
        follows:

        .. code::

            "module/function/value1+value2+..."

        Where the values are those of the ``arguments`` field. If no values are
        available, the last section is replaced by "None".

        Args:
            res: The results to add. If None, this method does nothing.
            arg_names: An optional list of argument names to filter which ones should be
                used to create the key.

        Notes:
            This method accepts None as the first argument to simplify its usage when a
            test function returns Results | None.

            The values are stringified with ``str()``.
        """
        if res is None:
            return
        key = f"{res.module}/{res.function}/"
        if arg_names is not None:
            values = [
                str(val) for arg, val in res.arguments.items() if arg in arg_names
            ]
        else:
            values = [str(val) for val in res.arguments.values()]
        if values:
            key += "+".join(values)
        else:
            key += "None"
        self[key] = res

    def check(self) -> bool:
        """Returns True if all results return True."""
        return all([results.check() for results in self.values()])


class Console(RichConsole):
    """Modified Rich console.

    Adds a couple of methods for displaying and saving results.

    Args:
        file: An optional file object where the console will write its output. None
            defaults to stdout.
    """

    def __init__(self, file=None):
        super().__init__(file=file)

    def print_results(self, res: Results | ResultsDict) -> None:
        """Prints the results string representation.

        Disables Rich's highlighting to only show colours defined by our classes.

        Args:
            res: Either an instance of Results or ResultsDict.
        """
        self.print(str(res), highlight=False)

    def process_results(
        self,
        res: ResultsDict | Results,
        filename: str = "",
        no_save: bool = False,
        debug_data: bool | None = None,
    ) -> bool:
        """Displays and saves results.

        Displays the results obtained with two possible panels (the Rich boxes):

        - The first panel contains the per-test results. It is shown only when there are
          failed tests or if the verbosity is greater than WARNING.
        - The second panel contains the summary of the results, with a brief description
          of the types of tests (valid, etc.)

        Then, depending on ``filename`` and ``no_save``, it can prompt the user on
        whether to save the results to a file. This version always includes the per-test
        results, and does not use panels.

        Args:
            res: The results to display.
            filename: An optional file. If a string is passed, the results are saved to
                that file. If an empty string is passed, the user is prompted. If None,
                the results are not saved and the user is not prompted.
            no_save: If True, no results are saved and the user is not prompted.
                Overrides ``filename``.
            debug_data: Controls whether to save debug data when saving the results to a
                file. If True, debug data is appended. If False, it is skipped. If None,
                when saving the results the user is prompted.

        Returns:
            True if all tests passed, False otherwise (i.e. the boolean returned by the
            results' check() method).
        """
        self.print("\n")
        # Show (or not) per-test results.
        if isinstance(res, ResultsDict) and (
            not res.check() or logger.getEffectiveLevel() < logging.WARNING
        ):
            results = "\n\n".join([str(r) for r in res.values()])
            results_panel = Panel(results, title="Per-test results")
            self.print(results_panel)
        # Describe the types of tests.
        description = (
            "Valid tests     : "
            "valid inputs that the implementation should use correctly.\n"
        )
        description += (
            "Invalid tests   : "
            "invalid inputs that the implementation should reject.\n"
        )
        description += (
            "Acceptable tests: " "inputs for legacy cases or weak parameters."
        )
        self.print(Panel(description, title="Types of tests"))
        # Show results summary: give some general info like primitives tested and show
        # the total count of tests. Include CC version as subtitle for reference.
        if isinstance(res, ResultsDict):
            primitives = sorted({r.module for r in res.values()})
        else:
            primitives = [res.module]
        content = f"Primitives tested: {', '.join(primitives)}\n"
        content += str(res)
        version = importlib.metadata.version("crypto-condor")
        # Zero-pad the version, taking into account a special case for rc versions.
        if "rc" in version:
            ver, rc = version.split("rc")
            padded_version = datetime.datetime.strptime(ver, "%Y.%m.%d").strftime(
                "%Y.%m.%d"
            )
            padded_version += f"-rc{rc}"
        else:
            padded_version = datetime.datetime.strptime(version, "%Y.%m.%d").strftime(
                "%Y.%m.%d"
            )
        summary = Panel(
            content,
            title="Results summary",
            subtitle=f"crypto-condor {padded_version} by Quarkslab",
        )
        self.print(summary)
        if no_save:
            # Nothing more to do.
            return res.check()
        # Save results.
        if bool(filename) or Confirm.ask("Save the results to a file?", default=False):
            if debug_data is None:
                debug_data = Confirm.ask(
                    "Save debug data? (Increases file size considerably)", default=False
                )
            date = datetime.datetime.today()
            fmt_date = date.strftime("%Y-%m-%d_%H:%M:%S")
            filename = filename or Prompt.ask(
                "Filename to save? (.txt extension added automatically)",
                default=f"cc_{fmt_date}.txt",
            )
            if not filename.endswith(".txt"):
                filename += ".txt"
            with open(filename, "w") as file:
                printer = Console(file=file)
                printer.print("Test results")
                printer.print("============")
                printer.print()
                printer.print(f"Primitives tested: {', '.join(primitives)}")
                printer.print(f"Generated on     : {fmt_date.replace('_', ' ')}")
                printer.print(f"By crypto-condor : version {padded_version}")
                printer.print()
                printer.print(str(res))
                if isinstance(res, ResultsDict):
                    printer.print()
                    printer.print("Per-test results")
                    printer.print("----------------")
                    printer.print()
                    printer.print("\n\n".join([str(r) for r in res.values()]))
                if debug_data:
                    printer.print()
                    if isinstance(res, ResultsDict):
                        count = 0
                        num_res = len(res)
                        for name, r in res.items():
                            count += 1
                            header = f"Debug data: {name}"
                            line = "^" * len(header)
                            printer.print(header)
                            printer.print(line)
                            printer.print()
                            for data in track(
                                r.data.values(), f"Writing debug data {count}/{num_res}"
                            ):
                                printer.print(str(data))
                                # For TestInfo we have to print the debug data
                                # separately.
                                if isinstance(data, TestInfo):
                                    printer.print(str(data.data))
                    else:
                        header = "Debug data"
                        line = "^" * len(header)
                        printer.print(header)
                        printer.print(line)
                        printer.print()
                        for data in track(res.data.values(), "Writing debug data"):
                            printer.print("data", str(data))
                            # For TestInfo we have to print the debug data separately.
                            if isinstance(data, TestInfo):
                                printer.print(str(data.data))
        return res.check()


# --------------------------- Other ---------------------------------------------------


def get_appdata_dir() -> Path:
    """Returns an OS-dependent application data directory.

    Creates the directory *and its parents* if it doesn't exist.

    This directory is used to store application data such as the compiled internal
    implementation of AES.
    """
    home = Path.home()

    match sys.platform:
        case "linux":
            appdata = (
                Path(os.getenv("XDG_DATA_HOME", home / ".local/share"))
                / "crypto-condor"
            )
        case "win32" | "cygwin":
            appdata = (
                Path(os.getenv("LOCALAPPDATA", home / "AppData/Local"))
                / "crypto_condor"
            )
        case "darwin":
            appdata = home / "Library/Application Support" / "crypto-condor"
        case _:
            raise ValueError(
                f"Unsupported platform {sys.platform}, can't get appdata directory"
            )

    if not appdata.is_dir():
        # Using parents as the CI doesn't have a .local/share directory, and in any case
        # it's preferable to use mkdir rather than catch FileNotFound.
        appdata.mkdir(parents=True)
        logger.debug(f"Appdata directory created at {str(appdata)}")

    return appdata
