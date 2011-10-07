#!/usr/bin/env python

from distutils.core import setup

setup(
        name='jail',
        version='0.0.1',
        description='FreeBSD Jail handler',
        long_description='Provides startup and termination for FreeBSD Jails, including network, devfs, and filesystem management.',
        scripts=['scripts/pyjail'],
        packages=['jail'],
        )
