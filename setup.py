from setuptools import setup, find_packages

version = '0.11.0'

setup(name='pysecure',
      version=version,
      description="A complete Python SSH/SFTP library based on libssh.",
      long_description="""\
A complete Python SSH/SFTP library based on libssh.""",
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
      keywords='ssh sftp tcp',
      author='Dustin Oprea',
      author_email='myselfasunder@gmail.com',
      url='https://github.com/dsoprea/PySecure',
      license='GPL2',
      packages=['pysecure', 'pysecure.adapters', 'pysecure.calls', 'pysecure.constants'],
      include_package_data=True,
      zip_safe=False,
      install_requires=[],
      entry_points="""
      # -*- Entry points: -*-
      """,
      scripts=[]
      ),

