## Example Testing Commands
    `$ cd "${CRYPTO_HOME}/cli"`

    `$ a_file='lorem_ipsum_100.txt'`

    `$ time cat src/test/resources/$a_file | bin/crypto -c NTRU -e -t 4 | bin/crypto -c NTRU -d -t 4 > /tmp/$a_file && wc -l src/test/resources/$a_file /tmp/$a_file && md5sum src/test/resources/$a_file /tmp/$a_file && diff -q src/test/resources/$a_file /tmp/$a_file`

    `$ time cat src/test/resources/$a_file | bin/crypto -c XOR -e -t 4 -k 131072 | bin/crypto -c XOR -d -t 4 -k 131072 > /tmp/$a_file &&  wc -l src/test/resources/$a_file /tmp/$a_file && md5sum src/test/resources/$a_file /tmp/$a_file && diff -q src/test/resources/$a_file /tmp/$a_file`
