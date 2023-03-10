Common tasks
============

Authentication shortcuts
------------------------
.. seealso::
   All these methods and their documentation can be found in the :ref:`namespace_desfire__fs`.

.. doxygengroup:: authShortcuts
   :project: libSpookyAction
   :no-link:
   :outline:
   :content-only:

Generic filesystem helpers
--------------------------
These methods check for existence and automate multiple-command tasks, such as creating an app with a specific key.

.. seealso::
   All these methods and their documentation can be found in the :ref:`namespace_desfire__fs`.

.. doxygengroup:: fsHelpers
   :project: libSpookyAction
   :no-link:
   :outline:
   :content-only:

Creating read-only applications
-------------------------------
Read-only applications do not really exist in the Desfire world; there are read-only files. However, we can emulate
this behavior by creating a randomized key which we can then throw away. This is thus split into two steps,
:func:`desfire::fs::create_app_for_ro` (which creates an app with a randomized key, which is returned) and
:func:`desfire::fs::make_app_ro` (which forbids any further file creation).

.. note::
   If you keep the key, or create files that have :var:`desfire::free_access`
   to :member:`desfire::file_access_rights::write`, then of course those files **will** be writable.

.. seealso::
   All these methods and their documentation can be found in the :ref:`namespace_desfire__fs`.

.. doxygengroup:: roApps
   :project: libSpookyAction
   :no-link:
   :outline:
   :content-only:

Creating read-only files
------------------------
Read-only files might require multiple operations to be performed, as e.g. data files need to be created, then
written to, and then sealed to not be writable anymore. These methods are shortcuts for this.

.. seealso::
   All these methods and their documentation can be found in the :ref:`namespace_desfire__fs`.

.. doxygengroup:: roFiles
   :project: libSpookyAction
   :no-link:
   :outline:
   :content-only:

Creating read-only, free-to-read files
--------------------------------------
Helper methods to :func:`desfire::fs::create_ro_data_file` and :func:`desfire::fs::create_ro_value_file` that always
specify a :var:`desfire::free_access` for :member:`desfire::file_access_rights::read`, and
:enumerator:`desfire::file_security::none` for :member:`desfire::common_file_settings::security`.

.. seealso::
   All these methods and their documentation can be found in the :ref:`namespace_desfire__fs`.

.. doxygengroup:: roFreeFiles
   :project: libSpookyAction
   :no-link:
   :outline:
   :content-only:


Card-level operations
---------------------
.. seealso::
   All these methods and their documentation can be found in :class:`desfire::tag`.

.. doxygengroup:: card
   :project: libSpookyAction
   :no-link:
   :outline:
   :content-only:

.. doxygengroup:: cardAndApplication
   :project: libSpookyAction
   :no-link:
   :outline:
   :content-only:

Application management
----------------------
.. seealso::
   All these methods and their documentation can be found in :class:`desfire::tag`.

.. doxygengroup:: application
   :project: libSpookyAction
   :no-link:
   :outline:
   :content-only:

.. doxygengroup:: cardAndApplication
   :project: libSpookyAction
   :no-link:
   :outline:
   :content-only:

Generic file management
-----------------------
Commands to create and read/write files on the card.

.. seealso::
   All these methods and their documentation can be found in :class:`desfire::tag`.

.. doxygengroup:: data
   :project: libSpookyAction
   :no-link:
   :outline:
   :content-only:

Standard file operations
------------------------
.. seealso::
   All these methods and their documentation can be found in :class:`desfire::tag`.


.. doxygengroup:: standardFile
   :project: libSpookyAction
   :no-link:
   :outline:
   :content-only:

.. doxygengroup:: standardAndBackupFile
   :project: libSpookyAction
   :no-link:
   :outline:
   :content-only:

Backup file operations
----------------------
.. seealso::
   All these methods and their documentation can be found in :class:`desfire::tag`.

.. doxygengroup:: backupFile
   :project: libSpookyAction
   :no-link:
   :outline:
   :content-only:

.. doxygengroup:: standardAndBackupFile
   :project: libSpookyAction
   :no-link:
   :outline:
   :content-only:

.. doxygengroup:: committableFiles
   :project: libSpookyAction
   :no-link:
   :outline:
   :content-only:

Cyclic or linear record file operations
---------------------------------------
.. seealso::
   All these methods and their documentation can be found in :class:`desfire::tag`.

.. doxygengroup:: recordFile
   :project: libSpookyAction
   :no-link:
   :outline:
   :content-only:

.. doxygengroup:: committableFiles
   :project: libSpookyAction
   :no-link:
   :outline:
   :content-only:

Value file operations
---------------------
.. doxygengroup:: valueFile
   :project: libSpookyAction
   :no-link:
   :outline:
   :content-only:

.. doxygengroup:: committableFiles
   :project: libSpookyAction
   :no-link:
   :outline:
   :content-only:
