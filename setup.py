#!/usr/bin/env python
from setuptools import setup
import os

os.system('apt-get install libsctp1 libsctp-dev lksctp-tools')

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

version = '0.5'

setup(
    name='rockstar',
    version=version,
install_requires=requirements)