#!/usr/bin/env python3
from distutils.core import setup
version='0.3'

setup(
    name='fuse-httpfs',
    version=version,
    author='Yves Fischer',
    author_email='yvesf-git@xapek.org',
    packages=[ 'httpfs' ],
    scripts=['fuse-httpfs'],
    url='https://github.com/yvesf/fuse-httpfs',
    download_url="https://github.com/yvesf/fuse-httpfs/archive/v{}.tar.gz".format(version),
    license='LICENSE.txt',
    description='A fuse filesystem for common http Index of pages.',
    long_description=open('README.md').read(),
    install_requires=[
        "fusepy",
        "requests",
    ],
)
