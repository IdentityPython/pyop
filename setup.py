from setuptools import setup, find_packages

setup(
    name='pyop',
    version='2.1.0',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    url='https://github.com/IdentityPython/pyop',
    license='Apache 2.0',
    author='Rebecka Gulliksson',
    author_email='satosa-dev@lists.sunet.se',
    description='OpenID Connect Provider (OP) library in Python.',
    install_requires=[
        'oic>0.13.1',
        'pymongo'
    ]
)
