from setuptools import setup, find_packages

setup(
    name='vtscanx',
    version='2.0.0',
    author='Amine Bououd',
    description='VirusTotal Threat Intelligence Toolkit',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    packages=find_packages(),
    install_requires=['requests'],
    python_requires='>=3.10',
    entry_points={
        'console_scripts': [
            'vtscanx=vtscanx.cli:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Topic :: Security',
    ],
)
