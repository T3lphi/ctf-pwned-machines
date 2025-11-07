# 🧩 Breaking RSA — Walkthrough (sem flags)

> **Quest:** Explorar a máquina *Breaking RSA* para entender falhas em implementações RSA e técnicas de fatoração/recuperação de chaves.  
> **Plataforma:** Lab privado / CTF TryHackMe 
> **Dificuldade:** Medium  
> **Data:** 2025-11-07  
> **Autor:** T3lphi, o Aprendiz das Sombras Digitais

---

## 📁 Visão geral da máquina
Breaking RSA é uma máquina focada em **criptografia**: a superfície de ataque inclui um serviço que fornece parâmetros RSA e permite que o atacante interaja com operações criptográficas. A vulnerabilidade explorada aqui é **uma implementação frágil/uso inseguro do RSA** que permite recuperar a chave privada através de ataque matemático (fatoração ou vulnerabilidade algorítmica).

> **Importante:** Este documento **não** contém flags. O objetivo é explicar metodologia, comandos e raciocínio.

---

## 🕵️‍♂️ 1. Enumeração

**1.1 Descoberta de portas**
```bash
# varredura inicial (todas as portas)
nmap -sS -sV -p- -T4 <IP>
# varredura mais precisa nas portas descobertas
nmap -sC -sV -p 22,80,12345 <IP>
