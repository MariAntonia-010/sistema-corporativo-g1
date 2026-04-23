# Sistema de Documentos Seguros

Avaliação G1 — Segurança de Sistemas  
Professor: Fábio Castro

---

## Sobre

Implementação prática de criptografia aplicada a um sistema corporativo de troca de documentos entre setores (RH, Jurídico, Financeiro).

## Cenários implementados

| Cenário | Problema | Solução |
|--------|----------|---------|
| 1 | Proteger o conteúdo durante a transmissão | Criptografia simétrica com AES-256-GCM |
| 2 | Confirmar autoria e integridade do documento | Assinatura digital com RSA + SHA-256 |
| 3 | Proteger arquivos armazenados no servidor | Arquivo salvo cifrado com AES-256-GCM |
| 4 | Trocar a chave AES sem expor segredos | Chave AES cifrada com RSA-OAEP |

## Como executar

**1. Instalar a dependência:**
```bash
pip install cryptography
```

**2. Rodar o código:**
```bash
python seguranca_corporativa.py
```

## O que o programa demonstra

- Conteúdo original do documento antes de cifrar
- Como o arquivo fica ilegível no disco após a cifragem
- Envio seguro com documento cifrado, assinatura e chave empacotada
- Recebimento e verificação pelo setor destinatário
- Detecção automática de adulteração do documento
