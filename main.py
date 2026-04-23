import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# Gerar chaves RSA para cada setor

def gerar_chaves():
    chave_privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    chave_publica = chave_privada.public_key()
    return chave_privada, chave_publica


 
# Cenário 1 - Envio de documentos entre setores
# Usar AES para cifrar e decifrar o documento

def cifrar(documento):
    chave = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    cifrado = AESGCM(chave).encrypt(nonce, documento, None)
    return chave, nonce, cifrado

def decifrar(chave, nonce, cifrado):
    return AESGCM(chave).decrypt(nonce, cifrado, None)



# Cenário 2 - Confirmação de autoria
# Assinar e verificar o documento com RSA

def assinar(chave_privada, documento):
    return chave_privada.sign(documento, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

def verificar(chave_publica, documento, assinatura):
    try:
        chave_publica.verify(
            assinatura, 
            documento,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    


 
# Cenário 3 - Proteção de arquivos armazenados
# Salvar e ler arquivo cifrado no servidor

chave_servidor = AESGCM.generate_key(bit_length=256)

def salvar_cifrado(nome, documento):
    nonce = os.urandom(12)
    cifrado = AESGCM(chave_servidor).encrypt(nonce, documento, None)
    with open(nome, 'wb') as f:
        f.write(nonce + cifrado)

    

def ler_cifrado(nome):
    with open(nome, 'rb') as f:
        dados = f.read()
    return AESGCM(chave_servidor).decrypt(dados[:12], dados[12:], None)



# Cenário 4 - Troca segura de chaves

def empacotar_chave(chave_publica_dest, chave_aes):
    return chave_publica_dest.encrypt(
        chave_aes,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )


def desempacotar_chave(chave_privada_dest, chave_aes_cifrada):
    return chave_privada_dest.decrypt(
        chave_aes_cifrada,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )


#Envio e recebimento entre setores

def enviar(documento, chave_privada_remetente, chave_publica_dest):
    chave_aes, nonce, doc_cifrado = cifrar(documento)
    assinatura = assinar(chave_privada_remetente, documento)
    chave_empacotada = empacotar_chave(chave_publica_dest, chave_aes)

    return {
        "doc_cifrado": doc_cifrado,
        "nonce": nonce,
        "assinatura": assinatura,
        "chave_empacotada": chave_empacotada
    }


def receber(pacote, chave_privada_dest, chave_publica_remetente):
    chave_aes = desempacotar_chave(chave_privada_dest, pacote["chave_empacotada"])
    documento = decifrar(chave_aes, pacote["nonce"], pacote["doc_cifrado"])

    if not verificar(chave_publica_remetente, documento, pacote["assinatura"]):
        raise Exception("Assinatura inválida! Documento rejeitado")
    
    return documento



# ============================================================
# DEMONSTRAÇÃO
# ============================================================
 
print("=" * 55)
print("     SISTEMA DE DOCUMENTOS SEGUROS")
print("=" * 55)
 
# Gerando chaves de cada setor
privada_rh,       publica_rh       = gerar_chaves()
privada_juridico, publica_juridico = gerar_chaves()
 
print("\n[Cenário 4 - Troca de chaves]")
print("  Chave pública  RH:       ", publica_rh.public_numbers().e)
print("  Chave pública  Jurídico: ", publica_juridico.public_numbers().e)
print("  (chaves privadas mantidas em segredo em cada setor)")
 
# Cenário 3: salvar no servidor cifrado
print("\n[Cenário 3 - Armazenamento]")
documento = b"Contrato - Salario R$ 10.000 - Confidencial"
print("  Conteúdo original:  ", documento.decode())
salvar_cifrado("contrato.enc", documento)
 
with open("contrato.enc", "rb") as f:
    bytes_no_disco = f.read()
print("  Como ficou no disco:", bytes_no_disco[:40], "...")
print("  -> Ilegível sem a chave do servidor")
 
# Cenário 1, 2 e 4: RH envia para o Jurídico
print("\n[Cenários 1, 2 e 4 - Envio seguro]")
conteudo = ler_cifrado("contrato.enc")
pacote = enviar(conteudo, privada_rh, publica_juridico)
 
print("  Documento cifrado (trecho):", pacote["doc_cifrado"][:30], "...")
print("  Assinatura digital (trecho):", pacote["assinatura"][:20], "...")
print("  Chave AES empacotada (trecho):", pacote["chave_empacotada"][:20], "...")
print("  -> Em sistemas reais, nenhuma dessas informações seria legível")
 
# Jurídico recebe e valida
print("\n[Recebimento - Jurídico]")
recebido = receber(pacote, privada_juridico, publica_rh)
print("  Assinatura verificada: OK")
print("  Documento decifrado:  ", recebido.decode())
 
# Teste de adulteração
print("\n[Teste de segurança - adulteração]")
print("  Simulando ataque: substituindo o documento")
pacote["doc_cifrado"] = b"documento_falso_inserido_por_atacante"
try:
    receber(pacote, privada_juridico, publica_rh)
except Exception as e:
    print(f"  Resultado: {e}")
    print("  -> Sistema bloqueou o documento corrompido")
 
print("\n" + "=" * 55)
print("  Todos os cenários executados - fechamento do sistema")
print("=" * 55)