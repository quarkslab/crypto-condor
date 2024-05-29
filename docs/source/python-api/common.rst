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

.. Define the arguments manually to hide the _nothing.NOTHING default of attrs.

.. autoclass:: Results(module, function, description, arguments, valid, invalid, acceptable, notes, data, _flags, _tids)
   :members:
   :member-order: bysource
   :special-members: __str__

.. autoclass:: TestInfo
   :members:
   :member-order: bysource

.. autoclass:: ResultsDict
   :members:
   :member-order: bysource
   :special-members: __str__

.. autoclass:: DebugInfo
   :special-members: __str__

.. autoclass:: PassedAndFailed

Functions
---------

.. autofunction:: get_appdata_dir

