Python API
==========

|cc| can be used directly as a Python library, ``crypto_condor``. Each supported
primitive has its own module under ``crypto_condor.primitives``, which contains the
functions to test implementations, test their output, or run wrappers. To provide an
uniform interface for recording test results, some classes such as
:class:`~crypto_condor.primitives.common.Results` as grouped in the
:mod:`crypto_condor.primitives.common` module.

To interact with the test vectors used throughout |cc|, each primitive has its own
module under ``crypto_condor.vectors``, defining classes that load test vectors
according to the parameters being tested.

Finally, we bundle a modified version of the `TestU01
<https://simul.iro.umontreal.ca/testu01/tu01.html>`_ library. See
:mod:`crypto_condor.primitives.TestU01`.

.. toctree::
   :maxdepth: 1

   common

.. toctree::
   :maxdepth: 2

   primitives/index

.. toctree::
   :maxdepth: 1

   vectors/index
   TestU01
