# pkcs11-tools-go

## pkcs11keypair

A tool to generate a keypair inside a PKCS#11 crypto token.

# Configuration

`pkcs11keypair` can be configured by setting environment variables, but applies
it's own defaults in case a variable is unset.

*    `HSMLIB`: Path to HSM Module library to use (default `/usr/lib/softhsm/libsofthsm.so`)
*    `HSM_SLOT_ID`: Slot ID to use (default `0`)
*    `USER_PIN`: User PIN to login to token (default `0000`)
*    `KEY_LABEL`: Label to use for key (default `pkcs11keypair_label`)
*    `KEY_ID`: ID to use for key (default is a random value)
*    `RSA_SIZE`: Bit size for modulus in key generation (default is `2048`,
      minimum is `1024`)

# Usage

Usage example with SoftHSM (requires libsofthsm and pkcs11-tool):

1.   Prepare SoftHSM token and set configuration values

        ```sh
        # Create SoftHSM configuration
        echo "0:${PWD}/softhsm.db" > softhsm.conf
        # Set configuration variables
        export SOFTHSM_CONF=${PWD}/softhsm.conf
        export HSM_MODULE=/usr/lib/softhsm/libsofthsm.so
        export HSM_SLOT_ID=0
        export TOKEN_LABEL=softhsm-token
        export KEY_LABEL=some_key
        export KEY_ID=12345
        # Initialize SoftHSM slot.
        pkcs11-tool --module ${HSM_LIB} --slot ${HSM_SLOT} --login\
          --init-token --init-pin --label ${TOKEN_LABEL} 
        ```

(You will be prompted for SO PIN und User PIN. Don't mix them up)

2.  Build and run `pkcs11keypair`

        ```sh
        go build pkcs11keypair.go
        ./pkcs11keypair
        Using module /usr/lib/softhsm/libsofthsm.so, slot ID 0, user PIN 0000, key id '12345', key label 'some_key', rsa bit size 2048.
        Wanted slot id 0 and got slot id 0.
        HSM Info:
        Manufacturer ID SoftHSM
        Flags: 0
        Library Description: Implementation of PKCS11
        Library Version: {1 3}.
        Key pair generated:
        Public Key: 2
        Private Key: 1
        ```

3. Verify that the keypair has been generated:

        ```sh
        % pkcs11-tool --module ${HSM_LIB} --so-pin 0000 --pin 0000 --login -O
        Using slot 0 with a present token (0x0)
        Public Key Object; RSA 2048 bits
          label:      some_key
          ID:         3132333435
          Usage:      encrypt, verify, wrap
        Private Key Object; RSA
          label:      some_key
          Usage:      decrypt, sign, unwrap
       ```
