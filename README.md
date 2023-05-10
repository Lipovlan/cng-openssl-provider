# OpenSSL provider using Cryptography API: Next Generation

Basic OpenSSL provider implementation that uses Windows Cryptography API: Next generation. It is primarily
meant to be a stepping stone for anybody wanting to implement their own provider. The functionality of
this provider is in greater detail in the section `This providers functionality`. 

Any feedback or pull requests are welcome.

The code is licensed under the MIT license, in case anybody would like to have even more permissive license,
create an issue, and I'm going to try and find a solution.

## Prerequisites for usage: 
  * OpenSSL 3.0.0+ (should be 3.2.0 compatible as well)
  * Windows with CNG support

## Prerequisites for compilation:
  * Prerequisites for usage
  * Visual Studio with C++ compilation packages
  * Strawberry Perl
  * NASM

Add NASM and Strawberry Perl to `PATH`.

```
cpan -i Text::Template
cpan -i Test::More
```

Now you should be ready for the next step.

## Compilation of OpenSSL:
These commands compile the 64 bit version. Modify the first and third line to compile for other platforms.

```
C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat” amd64
cd "C:\path\to\root\of\openssl\repo"
perl Configure VC-WIN64A -d no-shared enable-trace no-engine
nmake
nmake test
nmake install_ssldirs install_sw
```
Optionally also run `nmake install install_docs`.

## Compilation of this project
```
cmake -S . -B ./ custom-build-directory
2 cmake --build ./ custom-build-directory --target cng_provider
3 cmake --build ./ custom-build-directory --target install
4 cmake --build ./ custom-build-directory --target client
```


## This providers functionality
This provider allows retrieval of certificates and their associated keys stored in Windows system stores. Associated
keys can be used to sign digests with SHA2-256, 386 and 512 using OpenSSL API (with the work being done by CNG so
non-exportable private keys can be used as well).
## Usage of this provider
To load this provider use the name `cng_provider` in either the `-provider` command line argument where supported or
in `OSSL_PROVIDER_load()`. To maintain full functionality od OpenSSL, also load the `default` provider.

This provider requires a URI with `cng://` schema. After the schema comes the Windows system store name. Currently
supported are:
```
cng://CA
cng://MY
cng://ROOT
```

## Example usage
An example of how one might write code with this provider, that loads a specific certificate from the Windows store,
can be found in the `client` folder.
