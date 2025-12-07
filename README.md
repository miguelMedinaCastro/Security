# Antes de rodar o código execute os comandos abaixo para gerar as chaves:

## Gerar Chaves RSA

openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Gerar chave AES e IV
openssl rand -out aes_key.bin 32
openssl rand -out aes_iv.bin 16

# Gerar chave de 16 bytes e IV de 8 bytes 
openssl rand -out blowfish_key.bin 16
openssl rand -out blowfish_iv.bin 8