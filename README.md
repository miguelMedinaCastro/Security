# Antes de rodar o código execute os comandos abaixo para gerar as chaves:

## Gerar Chaves RSA

openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

## Gerar chave AES e IV
openssl rand -out aes_key.bin 32
openssl rand -out aes_iv.bin 16

## Gerar chave Blowfish e IV 
openssl rand -out blowfish_key.bin 16
openssl rand -out blowfish_iv.bin 8

## instruções para rodar o código
depois de rodar os comandos acima para gerar as chaves, basta rodar: ./bin/binary arquivo_1MB.bin public.pem private.pem aes_key.bin aes_iv.bin blowfish_key.bin blowfish_iv.bin
as chaves já estão inclusas para testar mas pra testar com tamanhos de chaves diferentes só lançar os comandos de chaves acima novamente e alterar os tamanhos.
 
