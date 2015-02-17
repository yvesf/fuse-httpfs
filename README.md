fuse-httpfs
===========

python-requests based fuse read-only filesystem

Requirements
------------

* fusepy

* requests
* fusepy

Usage
-----

### Setup

Create a directory to be used as a mountpoint.

### Starting

run with --help

### Using

* access the mountpoint
* open directory for schema (http/https)
* open an (maybe non-existing) directoring with the desired hostname


Remote machines configure in ~/.netrc will appear automatically. python-requests will pick-up the authentication infos from .netrc
