#!/usr/bin/env python

import os

from pip.req import parse_requirements
from setuptools import setup

install_reqs = parse_requirements(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                               'requirements.txt'), session='None')

setup(
    name='apsconnectcli',
    author='Ingram Micro',
    version='1.7.15',
    keywords='aps apsconnect connector automation',
    extras_require={
        ':python_version<="2.7"': ['backports.tempfile==1.0rc1']},
    packages=['apsconnectcli'],
    description='A command line tool for APS connector installation on Odin Automation in '
                'the relaxed way.',
    url='https://github.com/ingrammicro/apsconnect-cli',
    license='Apache Software License',
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
