## Introduction
Crypto may be used as a library to encrypt/decrypt data or called as a command
line tool which reads/writes to/from stdin/stdout.

## Library Methods
* com.tiffanytimbric.crypto.ntrutil.NtrUtil
  * encrypt(...)
  * decrypt(...)
* com.tiffanytimbric.crypto.nooputil.XorUtil
  * encrypt(...)
  * decrypt(...)
* com.tiffanytimbric.crypto.nooputil.NoopUtil
  * encrypt(...)
  * decrypt(...)

## Command Line Usage
Please read usage-<cryptosystem>.txt which you will find within the conf
folder.

## Usage Examples
You may want to add the path to this project's "bin" to your shell's PATH
environment variable.  The below examples assume the current working directory
(CWD) of the shell equals the root folder of this project.

### Encrypting Streams

    $ echo 'Hello, World!' | bin/crypto -c XOR -e | bin/crypto -c XOR -d

### Encrypting Files

    $ wc -l lorem_ipsum_100.txt

    $ cat lorem_ipsum_100.txt | bin/crypto -c XOR -e | bin/crypto -c XOR -d > /tmp/a_file.txt && wc -l lorem_ipsum_100.txt /tmp/a_file.txt && diff -q lorem_ipsum_100.txt /tmp/a_file.txt
    $ rm /tmp/a_file.txt

    $ cat lorem_ipsum_100.txt | bin/xorutil -e | bin/xorutil -d  > /tmp/a_file.txt && wc -l lorem_ipsum_100.txt /tmp/a_file.txt && diff -q lorem_ipsum_100.txt /tmp/a_file.txt
    $ rm /tmp/a_file.txt

    $ cat lorem_ipsum_100.txt | bin/crypto -c NTRU -e | bin/crypto -c NTRU -d  > /tmp/a_file.txt && wc -l lorem_ipsum_100.txt /tmp/a_file.txt && diff -q lorem_ipsum_100.txt /tmp/a_file.txt
    $ rm /tmp/a_file.txt

    $ cat lorem_ipsum_100.txt | bin/ntrutil -e | bin/ntrutil -d  > /tmp/a_file.txt && wc -l lorem_ipsum_100.txt /tmp/a_file.txt && diff -q lorem_ipsum_100.txt /tmp/a_file.txt
    $ rm /tmp/a_file.txt

### Encrypting Tar Archives

    $ cp -v lorem_ipsum_100.txt lorem_ipsum_100.2.txt
    $ tar -I 'bin/crypto -c XOR -e' -cf lorem_ipsum_100.2.txt.txor lorem_ipsum_100.2.txt
    $ rm lorem_ipsum_100.2.txt

    $ tar -I 'bin/crypto -c XOR' -xf lorem_ipsum_100.2.txt.txor
    $ diff -q lorem_ipsum_100.txt lorem_ipsum_100.2.txt
    $ rm lorem_ipsum_100.2.txt*

## Code Analysis
This Java code includes two separate implementation techiques for
multi-threaded/concurrent processing, one using the JDK's ExecutorServices and
another using RxJava 3.x.  The RxJava implementation is less readable,
less concise.  The significant additional features RxJava offers are not used
in this application as they are not needed.  RxJava offers no benefits to this
application.  It was introduced merely as a coding exercise.
