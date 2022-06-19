## Introduction
Crypto may be used as a library to encrypt/decrypt data or called as a command
line tool which reads/writes to/from stdin/stdout.

## Library Methods
* com.tiffanytimbric.crypto.ntru.NtrCryptosystem
  * encrypt(...)
  * decrypt(...)
* com.tiffanytimbric.crypto.noop.XorCryptosystem
  * encrypt(...)
  * decrypt(...)
* com.tiffanytimbric.crypto.noop.NoopCryptosystem
  * encrypt(...)
  * decrypt(...)

## Command Line Usage
Please read usage-<cryptosystem>.txt which you will find within the conf
folder.

## Usage Examples
You may want to add the path to this project's "bin" to your shell's PATH
environment variable.  The below examples assume the current working directory
(CWD) of the shell equals the "cli" folder of this project.

    $ cd "${CRYPTO_HOME}/cli"

### Encrypting Streams

    $ echo 'Hello, World!' | bin/crypto -c XOR -e | bin/crypto -c XOR -d

### Encrypting Files

    $ a_file='src/test/resources/lorem_ipsum_100.txt'

    $ cat src/test/resources/$a_file | bin/crypto -c XOR -e | bin/crypto -c XOR -d > /tmp/$a_file && wc -l src/test/resources/$a_file /tmp/$a_file && diff -q src/test/resources/$a_file /tmp/$a_file
    $ rm /tmp/$a_file

    $ cat src/test/resources/$a_file | bin/crypto -c XOR -e | bin/crypto -c XOR -d  > /tmp/$a_file && wc -l src/test/resources/$a_file /tmp/$a_file && diff -q src/test/resources/$a_file /tmp/$a_file
    $ rm /tmp/$a_file

    $ cat src/test/resources/$a_file | bin/crypto -c NTRU -e | bin/crypto -c NTRU -d  > /tmp/$a_file && wc -l src/test/resources/$a_file /tmp/$a_file && diff -q src/test/resources/$a_file /tmp/$a_file
    $ rm /tmp/$a_file

    $ cat src/test/resources/$a_file | bin/crypto -c NTRU -e | bin/crypto -c NTRU -d  > /tmp/$a_file && wc -l src/test/resources/$a_file /tmp/$a_file && diff -q src/test/resources/$a_file /tmp/$a_file
    $ rm /tmp/$a_file

### Encrypting Tar Archives

    $ cp -v $a_file lorem_ipsum_100.2.txt
    $ tar -I 'bin/crypto -c XOR -e' -cf lorem_ipsum_100.2.txt.txor lorem_ipsum_100.2.txt
    $ rm lorem_ipsum_100.2.txt*

    $ tar -I 'bin/crypto -c XOR' -xf lorem_ipsum_100.2.txt.txor
    $ diff -q $a_file lorem_ipsum_100.2.txt
    $ rm lorem_ipsum_100.2.txt*

### Base<16|32|64> Encoding Files

    $ cat src/test/resources/lorem_ipsum_5.txt | bin/crypto -c NOOP -e -b 64 > lorem_ipsum_5.txt.base65 && cat lorem_ipsum_5.txt.base64 | bin/crypto -c NOOP -d -b 64
    $ rm lorem_ipsum_5.txt*

## Code Analysis
This Java code includes two separate implementation techiques for
multi-threaded/concurrent processing, one using the JDK's ExecutorServices and
another using RxJava 3.x.  The RxJava implementation is less readable,
less concise.  The significant additional features RxJava offers are not used
in this application as they are not needed.  RxJava offers no benefits to this
application.  It was introduced merely as a coding exercise.
