#!/usr/bin/env python2.7

from setuptools import setup, find_packages
from setuptools.command.install import install

from ctypes import cdll
from ctypes.util import find_library

#import versioneer

#versioneer.VCS = 'git'
#versioneer.versionfile_source = 'pysecure/_version.py'
#versioneer.versionfile_build = 'pysecure/_version.py'
#versioneer.tag_prefix = ''
#versioneer.parentdir_prefix = 'pysecure-'

def pre_install():
    print("Verifying that libssh.so is accessible.")

    _LIBSSH_FILEPATH = find_library('libssh')
    if _LIBSSH_FILEPATH is None:
        _LIBSSH_FILEPATH = 'libssh.so'

    try:
        cdll.LoadLibrary(_LIBSSH_FILEPATH)
    except OSError:
        print("libssh can not be loaded.")
        raise

class custom_install(install):
    def run(self):
        pre_install()
        install.run(self)

#cmdclass = versioneer.get_cmdclass()
cmdclass = {}

cmdclass['install'] = custom_install

long_description = "A complete Python SSH/SFTP library based on libssh. This "\
                   "libraries offers [nearly] complete functionality, "\
                   "including elliptic cryptography support."

setup(name='pysecure',
      version='0.11.8',#versioneer.get_version(),
      description="A complete Python SSH/SFTP library based on libssh.",
      long_description=long_description,
      classifiers=['Development Status :: 3 - Alpha', 
                   'Intended Audience :: Developers',
                   'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
                   'Programming Language :: Python',
                   'Programming Language :: Python :: 2',
                   'Programming Language :: Python :: 3',
                   'Topic :: System :: Networking',
                   'Topic :: Software Development :: Libraries :: Python Modules',
                   'Topic :: System :: System Shells',
                   'Topic :: Terminals',
                  ],
      keywords='ssh sftp',
      author='Dustin Oprea',
      author_email='myselfasunder@gmail.com',
      url='https://github.com/dsoprea/PySecure',
      license='GPL2',
      packages=['pysecure', 'pysecure.adapters', 'pysecure.calls', 'pysecure.constants'],
      include_package_data=True,
      zip_safe=False,
      install_requires=[],
      scripts=[],
      cmdclass=cmdclass,
),

