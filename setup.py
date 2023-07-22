from Cython.Build import cythonize
from setuptools import Extension, setup

setup(
    ext_modules=cythonize(Extension('mirfatif.fs_watcher.fa_notify', ['native/fa_notify-bind.pyx']))
)
