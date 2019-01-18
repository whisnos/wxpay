#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: www.debug5.com

from setuptools import setup

import pywxpay

setup(
    name='pywxpay',
    version='0.1',
    description='python wxpay sdk.',
    author='http://www.debug5.com/',
    url='https://github.com/whisnos/wxpay',
    author_email='whisnos@163.com',
    license='BSD',
    platforms='any',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Utilities',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],

    install_requires=[
        'xmltodict',
        'requests'
    ],

    py_modules=['pywxpay', ],

)