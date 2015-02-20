#!/usr/bin/env python3
from distutils.core import setup
version='0.2'

setup(
    name='fuse-httpfs',
    version=version,
    author='Yves Fischer',
    author_email='yvesf-git@xapek.org',
    packages=[ ],
    scripts=['fuse-httpfs'],
    url='https://github.com/yvesf/fuse-httpfs',
    download_url="https://github.com/yvesf/fuse-httpfs/archive/v{}.tar.gz".format(version),
    license='LICENSE.txt',
    description='A fuse filesystem for common http Index of pages.',
    long_description=open('README.txt').read(),
    install_requires=[
        "fusepy",
        "requests",
    ],
)
