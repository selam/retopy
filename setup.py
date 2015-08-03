from setuptools import find_packages, setup

setup(
    name='retopy',
    version='0.1.dev1',
    packages=['retopy'],
    url='https://github.com/selam/retopy',
    license='Apache',
    author='Timu Eren',
    author_email='selamtux@gmail.com',
    description="Easy TCP servers with Tornado's ioloop.",
    install_requires=['tornado'],
)
