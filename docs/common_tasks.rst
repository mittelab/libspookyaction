Common tasks
============

Authentication shortcuts
------------------------
.. seealso::
   All these methods and their documentation can be found in the :ref:`namespace_desfire__fs`.

* :func:`desfire::fs::logout_app`
* :func:`desfire::fs::login_app`

Generic filesystem helpers
--------------------------
These methods check for existence and automate multiple-command tasks, such as creating an app with a specific key.

.. seealso::
   All these methods and their documentation can be found in the :ref:`namespace_desfire__fs`.

* :func:`desfire::fs::create_app`
* :func:`desfire::fs::delete_file_if_exists`
* :func:`desfire::fs::delete_app_if_exists`
* :func:`desfire::fs::does_file_exist`
* :func:`desfire::fs::which_files_exist`
* :func:`desfire::fs::does_app_exist`

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

* :func:`desfire::fs::make_app_ro`
* :func:`desfire::fs::create_app_for_ro`

Creating read-only files
------------------------
Read-only files might require multiple operations to be performed, as e.g. data files need to be created, then
written to, and then sealed to not be writable anymore. These methods are shortcuts for this.

.. seealso::
   All these methods and their documentation can be found in the :ref:`namespace_desfire__fs`.

* :func:`desfire::fs::create_ro_data_file`
* :func:`desfire::fs::create_ro_value_file`

Creating read-only, free-to-read files
--------------------------------------
Helper methods to :func:`desfire::fs::create_ro_data_file` and :func:`desfire::fs::create_ro_value_file` that always
specify a :var:`desfire::free_access` for :member:`desfire::file_access_rights::read`, and
:enumerator:`desfire::file_security::none` for :member:`desfire::common_file_settings::security`.

.. seealso::
   All these methods and their documentation can be found in the :ref:`namespace_desfire__fs`.

* :func:`desfire::fs::create_ro_free_data_file`
* :func:`desfire::fs::create_ro_free_value_file`


Card-level operations
---------------------
.. seealso::
   All these methods and their documentation can be found in :class:`desfire::tag`.

* :func:`desfire::tag::active_app`
* :func:`desfire::tag::active_cipher_type`
* :func:`desfire::tag::active_key_no`
* :func:`desfire::tag::authenticate`
* :func:`desfire::tag::change_key`
* :func:`desfire::tag::format_picc`
* :func:`desfire::tag::get_card_uid`
* :func:`desfire::tag::get_free_mem`
* :func:`desfire::tag::get_info`
* :func:`desfire::tag::select_application`
* :func:`desfire::tag::set_configuration`

Application management
----------------------
.. seealso::
   All these methods and their documentation can be found in :class:`desfire::tag`.

* :func:`desfire::tag::active_cipher_type`
* :func:`desfire::tag::active_key_no`
* :func:`desfire::tag::authenticate`
* :func:`desfire::tag::change_app_settings`
* :func:`desfire::tag::change_key`
* :func:`desfire::tag::create_application`
* :func:`desfire::tag::delete_application`
* :func:`desfire::tag::format_picc`
* :func:`desfire::tag::get_app_settings`
* :func:`desfire::tag::get_application_ids`
* :func:`desfire::tag::get_key_version`
* :func:`desfire::tag::select_application`

Generic file management
-----------------------
Commands to create and read/write files on the card.

.. seealso::
   All these methods and their documentation can be found in :class:`desfire::tag`.

* :func:`desfire::tag::change_file_settings`
* :func:`desfire::tag::command_parse_response`
* :func:`desfire::tag::command_response`
* :func:`desfire::tag::command_status_response`
* :func:`desfire::tag::create_file`
* :func:`desfire::tag::delete_file`
* :func:`desfire::tag::get_file_ids`
* :func:`desfire::tag::get_file_settings`
* :func:`desfire::tag::get_specific_file_settings`

Standard file operations
------------------------
.. seealso::
   All these methods and their documentation can be found in :class:`desfire::tag`.

* :func:`desfire::tag::create_file`
* :func:`desfire::tag::read_data`
* :func:`desfire::tag::write_data`

Backup file operations
----------------------
.. seealso::
   All these methods and their documentation can be found in :class:`desfire::tag`.

* :func:`desfire::tag::abort_transaction`
* :func:`desfire::tag::commit_transaction`
* :func:`desfire::tag::create_file`
* :func:`desfire::tag::read_data`
* :func:`desfire::tag::write_data`

Cyclic or linear record file operations
---------------------------------------
.. seealso::
   All these methods and their documentation can be found in :class:`desfire::tag`.

* :func:`desfire::tag::abort_transaction`
* :func:`desfire::tag::clear_record_file`
* :func:`desfire::tag::commit_transaction`
* :func:`desfire::tag::create_file`
* :func:`desfire::tag::read_parse_records`
* :func:`desfire::tag::read_records`
* :func:`desfire::tag::write_record`

Value file operations
---------------------
.. seealso::
   All these methods and their documentation can be found in :class:`desfire::tag`.

* :func:`desfire::tag::abort_transaction`
* :func:`desfire::tag::commit_transaction`
* :func:`desfire::tag::credit`
* :func:`desfire::tag::debit`
* :func:`desfire::tag::get_value`
* :func:`desfire::tag::limited_credit`
