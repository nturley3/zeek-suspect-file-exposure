Sensitive File Exposure Detection
======================

Zeek module which detects access to possibly sensitive files that are exposed.
This includes files such as source code files, database files, config files
such as .htaccess and others. 

It is intended that this module will be enhanced to include detection of
strong and weak mime types, as well as payload sample extraction for non-binary
files. 

Installation/Upgrade
------------

This script was written and tested

Install the latest version through the Zeek package manager:

	zkg refresh
	zkg install https://github.com/nturley3/zeek-suspect-file-exposure

To upgrade the package:

	zkg refresh
	zkg upgrade  nturley3/zeek-suspect-file-exposure

See the [Zeek Package Manager Docs](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html) for more information.


## Configuration

No additional Zeek configuration is necessary for this module.


Generated Outputs
-----

This script generates multiple notices:

| Field Value | Description |
| -- | -- |
| HTTPFileExposure:Office_File | This indicates access to a MS Office type file (excel, PST etc). |
| HTTPFileExposure:Database_File | This indicates access to a database file, SQL dump etc. |
| HTTPFileExposure:Sensitive_File | This indicates access to a general sensntive file (.htaccess, wordpress config etc). |
| HTTPFileExposure:SourceCode_File | This indicates access to a potentially sensitive source code file (python, perl, ruby etc). |


## About
Written by [@nturley3](https://github.com/nturley3).