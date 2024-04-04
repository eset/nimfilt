#!/usr/bin/env python3
# -*- encoding: utf8 -*-
#
# Copyright (c) 2024 ESET
# Author: Alexandre Côté Cyr <alexandre.cote@eset.com>
# See LICENSE file for redistribution.

from setuptools import setup

long_description = \
"""
Nimfilt
======
Nimfilt is a collection of modules and scripts to help with analyzing
[Nim](https://github.com/nim-lang/Nim/) binaries. It started out as a CLI
demangling tool inspired by `c++filt`. It evolved into a larger set of tools
for analyzing Nim, but the original name stuck.
"""

setup(name='nimfilt',
      version='1.0',
      description='A collection of modules and scripts to help with analyzing Nim binaries',
      long_description=long_description,
      long_description_content_type="text/markdown",
      author='Alexandre Côté Cyr',
      author_email='alexandre.cote@eset.com',
      url='https://www.github.com/eset/nimfilt',
      python_requires=">=3",
      py_modules=["nimfilt"],
      license="BSD",
      entry_points= {
          "console_scripts": [ "nimfilt=nimfilt:main" ]
      },
      classifiers=[
          "Development Status :: 5 - Production/Stable",
          "License :: OSI Approved :: BSD License",
          "Programming Language :: Python :: 3",
      ],
)
