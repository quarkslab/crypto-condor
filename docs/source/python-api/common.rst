:tocdepth: 3

Common
======

.. automodule:: crypto_condor.primitives.common

.. currentmodule:: crypto_condor.primitives.common

Test types
----------

.. autoenum:: TestType

Results
-------

Results for individual test vectors can be stored with the new :class:`TestInfo` class,
or the old :class:`DebugInfo` class. They define a common set of attributes that are
required for each individual test, such as the test type as described by
:enum:`TestType`.

These individual results are grouped by primitive, function, and parameters in the
:class:`Results` class. To combine multiple variations of parameters or different
primitives, the :class:`ResultsDict` class should be used.

.. Define the arguments manually to hide the _nothing.NOTHING default of attrs.

.. autoclass:: ResultsDict
   :members:
   :member-order: bysource
   :special-members: __str__

.. autoclass:: Results(module, function, description, arguments, valid, invalid, acceptable, notes, data, _flags, _tids)
   :members:
   :member-order: bysource
   :special-members: __str__

.. autoclass:: TestInfo
   :members:
   :member-order: bysource

.. autoclass:: DebugInfo
   :special-members: __str__

.. autoclass:: PassedAndFailed

Functions
---------

For functions that have to persist application data, the :func:`get_appdata_dir`
function returns the path to use.

.. autofunction:: get_appdata_dir

Console
-------

.. autoclass:: Console
   :members:
