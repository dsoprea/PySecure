from setuptools import setup, find_packages

version = '0.6.2'

setup(name='pysecure',
      version=version,
      description="A complete Python SSH/SFTP library based on libssh.",
      long_description="""\
A complete Python SSH/SFTP library based on libssh.""",
      classifiers=['Development Status :: 3 - Alpha', 
                   'Intended Audience :: Developers',
                   'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
                   'Programming Language :: Python',
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
      packages=['pysecure'],
      include_package_data=True,
      zip_safe=True,
      install_requires=[],
      entry_points="""
      # -*- Entry points: -*-
      """,
      scripts=[]
      ),

