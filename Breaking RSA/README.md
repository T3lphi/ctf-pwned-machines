# 🧩 Breaking RSA — Walkthrough (sem flags)

> **Quest:** Explorar a máquina *Breaking RSA* para entender falhas em implementações RSA e técnicas de fatoração/recuperação de chaves.  
> **Plataforma:** TryHackMe (Lab privado / CTF)  
> **Dificuldade:** Medium  
> **Data:** 2025-11-07  
> **Autor:** T3lphi, o Aprendiz das Sombras Digitais

---

## 📁 Visão geral da máquina
Breaking RSA é uma máquina focada em **criptografia**. A superfície de ataque inclui um serviço que fornece parâmetros RSA ou arquivos públicos (por exemplo, `id_rsa.pub`). A vulnerabilidade explorada é uma **implementação frágil/uso inseguro do RSA** que permite recuperar a chave privada através de técnicas matemáticas (fatoração, ataques sobre expoente, ou shared factors entre módulos).

> **Importante:** Este documento **não** contém flags. O objetivo é explicar metodologia, comandos e raciocínio.

---

## 🕵️‍♂️ 1. Enumeração

**1.1 Descoberta de portas**
```bash
# exemplo simples de nmap para identificar serviços
nmap -sV 10.201.45.179
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-07 19:25 EST
Nmap scan report for 10.201.45.179
Host is up (0.16s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
******  ****  *****  *******
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.35 seconds
```

**1.2 Descoberta de diretórios**
```bash
gobuster dir -u http://10.201.45.179 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

```bash
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.201.45.179
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/***********          (Status: 301) [Size: 178] [--> http://10.201.45.179/***********/]
```
Então baixar o arquivo público id_rsa.pub, salve-o localmente e verifique tamanho/metadados, usando a command line 'stat'
```bash
stat id_rsa.pub                              
  File: id_rsa.pub
  Size: 725             Blocks: 8          IO Block: ****   regular file
Device: 8,1     Inode: 1837400     Links: 1
Access: (0664/-rw-rw-r--)  Uid: ( 1000/    kali)   Gid: ( 1000/    kali)
Access: 2025-11-07 18:51:36.920367680 -0500
Modify: 2025-11-07 18:51:15.511077498 -0500
Change: 2025-11-07 18:51:15.583041499 -0500
 Birth: 2025-11-07 18:51:15.507079500 -0500
```

## 🔍 2. Extrair o módulo N (modulus) da chave pública (id_rsa.pub)

**2.1 Converter OpenSSH .pub para PEM**
```bash
ssh-keygen -f id_rsa.pub -e -m PEM > key.pem
```
-f id_rsa.pub → arquivo de entrada

-e -m PEM → exporta para o formato PEM

**2.2 Extrair o Modulus (hex) com OpenSSL**
```bash
openssl rsa -pubin -in key.pem -noout -modulus
```
****Como retorna hexadecimal, passar de hexadecimal para inteiro e terá os 12 últimos caracteres.****

use a resposta do script anterior nesse, crie um arquivo .py mudandos os valores que se pede.
```bash
from sympy import factorint
n = <cole_o_valor_decimal_aqui>
print(factorint(n))
```
vai retornar algo como:
{******: 1, *******: 1}
cada um deles refere-se à uma variável, um é o P e o outro é o Q.

Use o script:

---

```bash
#!/usr/bin/env python3
"""
build_rsa_from_pq.py
Gera id_rsa (PEM) e id_rsa.pub (OpenSSH) a partir de p e q (inteiros).
USO: editar o arquivo e substituir p e q pelas tuas variáveis (ou adaptar para ler de entrada).
Dependências: pip install cryptography
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

# ========== <<< SUBSTITUA AQUI p e q >>> ==========
# Atenção: coloque AQUI os inteiros p e q que você conseguiu fatorar / obteve de forma legítima.
p = None  # ex: 1234567890123456789012345678901234567891
q = None  # ex: 9876543210987654321098765432109876543221
# ==================================================

# expoente público (comum)
e = 65537

def check_inputs(p, q):
    if p is None or q is None:
        raise SystemExit("ERROR: preencha as variáveis p e q no topo do script antes de rodar.")
    if p == q:
        raise SystemExit("ERROR: p e q são iguais — verifique os valores.")
    if p < 2 or q < 2:
        raise SystemExit("ERROR: p e q devem ser inteiros primos válidos (maiores que 1).")

def main():
    check_inputs(p, q)

    n = p * q
    phi_n = (p - 1) * (q - 1)

    # calcular d (inverso modular)
    try:
        d = pow(e, -1, phi_n)  # Python 3.8+
    except TypeError:
        # fallback (Euclides estendido)
        def egcd(a, b):
            if b == 0:
                return (1, 0, a)
            x, y, g = egcd(b, a % b)
            return (y, x - (a // b) * y, g)
        x, y, g = egcd(e, phi_n)
        if g != 1:
            raise SystemExit("ERROR: e não é inversível modulo phi(n).")
        d = x % phi_n

    # parâmetros CRT
    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = pow(q, -1, p)

    # montar objetos RSA
    private_numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=dmp1,
        dmq1=dmq1,
        iqmp=iqmp,
        public_numbers=rsa.RSAPublicNumbers(e=e, n=n)
    )

    private_key = private_numbers.private_key()

    # serializar chave privada (PKCS#1 PEM)
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # escrever id_rsa
    out_priv = "id_rsa"
    with open(out_priv, "wb") as f:
        f.write(pem_priv)
    os.chmod(out_priv, 0o600)

    # serializar chave pública em formato OpenSSH
    public_key = private_key.public_key()
    pub_openssh = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )
    out_pub = "id_rsa.pub"
    with open(out_pub, "wb") as f:
        f.write(pub_openssh + b"\n")

    print(f"Gerado {out_priv} (PEM) e {out_pub} (OpenSSH).")
    print("Permissões do id_rsa: 600")

if __name__ == "__main__":
    main()
```
O SSH do root está aberto;
use o comando, trocando o ip, se necessário:
```bash
ssh root@10.201.45.179 -i id_rsa
```
E a flag estará lá.

