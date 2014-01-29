from distutils.core import setup, Command


class PyTest(Command):

    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        import sys
        import subprocess
        errno = subprocess.call([sys.executable, 'runtests.py', '--cov', 'pypassdb'])
        raise SystemExit(errno)

setup(name='pypassdb',
      version='0.1.0',
      author='Naohiro Aota',
      author_email='naota@elisp.net',
      url='https://github.com/naota/pypassdb',
      packages=['pypassdb'],
      cmdclass={'test': PyTest},
      )
