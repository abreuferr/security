#!/bin/bash

export DFENCE_PKCS11_IP=200.201.208.61
export DFENCE_PKCS11_USER=senhasegura
export DFENCE_PKCS11_AUTO_RECONNECT=1
export MODULE_DINAMO=/usr/lib/libtacndp11.so
export PASSWORD=12345678
export HSM_PKCS11_NON_PRIVATE_OBJECTS_SUPPORT=1

# Listar o conteudo do HSM
pkcs11-tool -vv --module $MODULE_DINAMO -p $PASSWORD --login -O

# Chave AES:256
pkcs11-tool -vv --module $MODULE_DINAMO --login --pin $PASSWORD --keygen --key-type aes:32 --label "aes256"

# Chave AES:192
pkcs11-tool -vv --module $MODULE_DINAMO --login --pin $PASSWORD --keygen --key-type aes:24 --label "aes192"

# Chave AES:128
pkcs11-tool -vv --module $MODULE_DINAMO --login --pin $PASSWORD --keygen --key-type aes:16 --label "aes128"

# Chave RSA:512
pkcs11-tool -vv --module $MODULE_DINAMO --login --pin $PASSWORD --keypairgen --key-type rsa:512 --label "rsa512"