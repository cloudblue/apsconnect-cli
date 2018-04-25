#!/usr/bin/env python

import os
from os.path import abspath, dirname, join

from setuptools import setup

try:  # for pip >= 10
    from pip._internal.req import parse_requirements
except ImportError:  # for pip <= 9.0.3
    from pip.req import parse_requirements

install_reqs = parse_requirements(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                               'requirements.txt'), session='None')

here = abspath(dirname(__file__))

with open(join(here, 'VERSION')) as f:
    VERSION = f.read()

setup(
    name='apsconnectcli',
    author='Ingram Micro',
    version=VERSION,
    keywords='aps apsconnect connector automation',
    extras_require={
        ':python_version<="2.7"': ['backports.tempfile==1.0']},
    packages=['apsconnectcli'],
    description='A command line tool for APS connector installation on Odin Automation in '
                'the relaxed way.',
    url='https://github.com/ingrammicro/apsconnect-cli',
    license='Apache Software License',
    include_package_data=True,
    install_requires=[str(ir.req) for ir in install_reqs],
    entry_points={
        'console_scripts': [
            'apsconnect = apsconnectcli.apsconnect:main',
        ]
    },
    classifiers=[
        'Development Status :: 4 - Beta',

        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',

        'License :: OSI Approved :: Apache Software License',

        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',

        'Operating System :: OS Independent',
        'Operating System :: POSIX',
        'Operating System :: MacOS',
        'Operating System :: Unix',
    ],
)
