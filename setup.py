from setuptools import setup, find_packages

setup(
    name='pyop',
    version='3.4.0',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    url='https://github.com/IdentityPython/pyop',
    license='Apache 2.0',
    author='Rebecka Gulliksson',
    author_email='satosa-dev@lists.sunet.se',
    description='OpenID Connect Provider (OP) library in Python.',
    install_requires=[
        'oic >= 1.2.1',
        'pycryptodomex',
    ],
    extras_require={
        'mongo': 'pymongo >= 3.12, < 4.0',
        'redis': 'redis',
    },
)
