
import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'README.rst')) as f:
    README = f.read()

with open(os.path.join(here, 'CHANGES.txt')) as f:
    CHANGES = f.read()

requires = ['pyramid', 'repoze.who', 'unittest2']

setup(name='pyramid_whoauth',
      version='0.1.1',
      description='pyramid_whoauth',
      long_description=README + '\n\n' + CHANGES,
      classifiers=[
        "Programming Language :: Python",
        "Framework :: Pylons",
        "Topic :: Internet :: WWW/HTTP",
        ],
      author='Mozilla Services',
      author_email='services-dev@mozilla.org',
      url='https://github.com/mozilla-services/pyramid_whoauth',
      keywords='web pyramid pylons authentication',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      tests_require=requires,
      test_suite="pyramid_whoauth",
      paster_plugins=['pyramid'])
