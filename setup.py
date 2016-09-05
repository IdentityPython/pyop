from setuptools import setup, find_packages

setup(
    name='pyop',
    version='1.0.0',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    url='https://github.com/its-dirg/pyop',
    license='Apache 2.0',
    author='Rebecka Gulliksson',
    author_email='rebecka.gulliksson@umu.se',
    description='OpenID Connect Provider (OP) library in Python.',
    install_requires=[
        'oic >= 0.8.5.0',
        'pymongo'
    ]
)
