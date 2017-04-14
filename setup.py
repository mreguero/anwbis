#!/usr/bin/env python
try:
        from setuptools import setup
except ImportError:
        from distutils.core import setup

config = {
        'description': 'AnWbiS Amazon Account Access',
        'author': 'Luis Gonzalez and Javier Martin-Caro',
        'url': '',
        'download_url': '',
        'author_email': ['luis.gonzalez@beeva.com', 'javier.martincaro@beeva.com'],
        'version': '1.5.0',
        'install_requires': ['colorama >= 0.3.2', 'argparse >=1.2.2', 'boto >= 2.24.0', 'requests >= 2.9.1'],
        'packages': ['anwbis'],
        'scripts': [],
        'name': 'anwbis',
        'entry_points': {
                'console_scripts': [ 'anwbis = anwbis.anwbis:main' ]
        }
}
setup(**config)
