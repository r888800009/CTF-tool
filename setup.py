from setuptools import setup, find_packages

setup(
    name='r809pwnlib',
    version='0.1',
    packages=['r809pwnlib'],
    package_dir={'r809pwnlib': 'r809pwn'},  # Adjust the path accordingly
    install_requires=[
        "pwntools",
    ],
)