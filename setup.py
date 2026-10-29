from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='noiseprotocol',
    version='0.3.1',
    description='WhatsApp Noise handshakes for Python: XX, IK and ML-KEM-512 fallback',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/WhatsappWiki/whatsapp-noiseprotocol',
    project_urls={'Upstream': 'https://github.com/plizonczyk/noiseprotocol'},
    author='Piotr Lizonczyk',
    author_email='plizonczyk.public@gmail.com',
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux'
    ],
    keywords='whatsapp noise-protocol noiseprotocol python cryptography handshake x25519 aes-gcm xxfallback ml-kem-512 post-quantum',
    packages=find_packages(exclude=[
        'contrib', 'contrib.*', 'docs', 'docs.*',
        'tests', 'tests.*', 'examples', 'examples.*',
    ]),
    py_modules=['whatsapp_fallback'],
    install_requires=['cryptography>=2.8'],
    extras_require={'whatsapp-pq': ['pqcrypto==0.3.4']},
    python_requires='~=3.5',  # we like 3.5, 3.6, and beyond, but not 4.0
)
