# fuse-httpfs

python-requests based fuse read-only filesystem

## Usage

python3 dependencies:

* requests
* fusepy

### Mount

* Create a directory to be used as a mountpoint.
* run with --help

### Using

* access the mountpoint
* open directory for schema (http/https)
* open an (maybe non-existing) directoring with the desired hostname


Remote machines configure in ~/.netrc will appear automatically. python-requests will pick-up the authentication infos from .netrc


## Run the tests

     python3.4 -m unittest test
