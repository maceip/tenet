.. sphinxmix documentation master file, created by
   sphinx-quickstart on Sun Nov 13 20:36:25 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

The sphinxmix package documentation
===================================

This documentation relates to the `sphinxmix` package version |version|.

Installing
----------

Install using `pip` through the command::

	$ pip install sphinxmix

Basic usage
-----------

.. automodule:: sphinxmix
   :members:

Development
-----------

The git repository for ``sphinxmix`` can be cloned from here:
https://github.com/UCL-InfoSec/sphinx

The ``pytest`` unit tests and doctests of ``sphinxmix`` may be ran using ``tox`` simply through the command::

	$ tox

To upload a new distribution of ``sphinxmix`` the maintainer simply uses::

	$ python setup.py sdist upload


Core classes and functions
==========================

.. autoclass:: sphinxmix.SphinxParams.SphinxParams

.. autoclass:: sphinxmix.SphinxParams.Group_ECC

.. autoclass:: sphinxmix.SphinxParamsC25519.Group_C25519

Utility functions
-----------------

.. autofunction:: sphinxmix.SphinxClient.pki_entry

.. autofunction:: sphinxmix.SphinxClient.Nenc

.. autodata:: sphinxmix.SphinxClient.Relay_flag

.. autodata:: sphinxmix.SphinxClient.Dest_flag

.. autodata:: sphinxmix.SphinxClient.Surb_flag

.. autofunction:: sphinxmix.SphinxClient.PFdecode

.. autofunction:: sphinxmix.SphinxClient.rand_subset

Client functions
----------------
    
.. autofunction:: sphinxmix.SphinxClient.create_forward_message

.. autofunction:: sphinxmix.SphinxClient.receive_forward

Packaging messages
------------------

.. autofunction:: sphinxmix.SphinxClient.pack_message

.. autofunction:: sphinxmix.SphinxClient.unpack_message

Mix functions
-------------

.. autofunction:: sphinxmix.SphinxNode.sphinx_process

SURB functions
--------------

.. autofunction:: sphinxmix.SphinxClient.create_surb

.. autofunction:: sphinxmix.SphinxClient.package_surb

.. autofunction:: sphinxmix.SphinxClient.receive_surb


Ultrix Format
=============

Mix functions
-------------

.. autofunction:: sphinxmix.UltrixNode.ultrix_process

Client functions
----------------
    
.. autofunction:: sphinxmix.UltrixClient.create_forward_message

.. autofunction:: sphinxmix.UltrixClient.receive_forward

SURB functions
--------------

.. autofunction:: sphinxmix.UltrixClient.create_surb

.. autofunction:: sphinxmix.UltrixClient.package_surb

.. autofunction:: sphinxmix.UltrixClient.decode_surb

.. autofunction:: sphinxmix.UltrixClient.receive_surb


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

