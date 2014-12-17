import os
try:
	from setuptools import setup
except ImportError:
	from distutils.core import setup

# Handle long_description this way in case __file__ isn't defined, as with eco
extra = {}
try:
	extra['long_description'] = open(os.path.join(os.path.dirname(__file__), 'README.txt')).read()
except:
	pass

setup(
	name="Symbolicator",
	py_modules=['symbolicator', ],
	author='Peter Hosey',
	url='http://boredzo.org/symbolicator/',
	version='1.0.1',
	license='BSD',
	description="The Symbolicator is a program to symbolicate crash logs generated on Mac OS X.",
	entry_points={'console_scripts': ['symbolicator=symbolicator:main', ],
  	              },
	**extra
)
