#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "/usr/include/dinamo.h" /* header do Dinamo */

#define HOST_ADDR       "200.201.208.61"
#define USER_ID         "senhasegura"
#define USER_PWD        "12345678"

#define ECDH_KEY_NAME       "ecdh_key"
#define ECDH_PAIR_KEY_NAME  "ecdh_pair_key"
#define ECDH_NEW_DERIVED_KEY  "ecdh_derived_key"
#define ECDH_KEY_ALG    (ALG_ECC_BRAINPOOL_P512T1)
void main()
{
    int nRet;
    struct AUTH_PWD authPwd;
    HSESSIONCTX hSession = NULL;
    HKEYCTX hKey = NULL;
    HKEYCTX hPairKey = NULL;
    BYTE pbPubKey[1024] = {0};
    DWORD dwPubKeyLen = sizeof(pbPubKey);
    BYTE pbSecret[1024] = {0};
    DWORD dwSecretLen = sizeof(pbSecret);

    //Inicializa as bibliotecas do Dinamo
    nRet = DInitialize(0);
    if(nRet)
    {
        printf("Falha na funcao: DInitialize \nCodigo de erro: %d\n", nRet);
        exit(1);
    }
    printf("Bibliotecas inicializadas.\n");
    
    //Inicializa a estrutura para conexão com o HSM
    strncpy(authPwd.szAddr, HOST_ADDR, sizeof(authPwd.szAddr));
    authPwd.nPort = DEFAULT_PORT;
    strncpy(authPwd.szUserId, USER_ID, sizeof(authPwd.szUserId));
    strncpy(authPwd.szPassword, USER_PWD, sizeof(authPwd.szPassword));
    nRet = DOpenSession(&hSession, SS_USER_PWD, (BYTE *)&authPwd, sizeof(authPwd), ENCRYPTED_CONN);
    if(nRet)
    {
        printf("Falha na funcao: DOpenSession \nCodigo de erro: %d\n", nRet);
        goto CLEAN;
    }
    printf("Sessao com o Dinamo estabelecida.\n");
    nRet = DGenerateKey(hSession, ECDH_KEY_NAME, ECDH_KEY_ALG, 0, &hKey);
    if(nRet)
    {
        printf("Falha ao gerar chave principal.\n");
        goto CLEAN;
    }
    printf("Chave principal gerada com sucesso.\n");
    nRet = DGenerateKey(hSession, ECDH_PAIR_KEY_NAME, ECDH_KEY_ALG, 0, &hPairKey);
    if(nRet)
    {
        printf("Falha ao gerar chave do par.\n");
        goto CLEAN;
    }
    printf("Chave do par gerada com sucesso.\n");
    
    nRet = DExportKey(hPairKey, NULL, PUBLICKEY_BLOB, 0, pbPubKey, &dwPubKeyLen);
    if(nRet)
    {
        printf("Falha ao exportar chave publica do par.\n");
        goto CLEAN;
    }
    printf("Chave publica do par exportada com sucesso.\n");
    
    nRet = DGenEcdhKey(hSession,
                       DN_GEN_KEY_KDF_RAW_SECRET,
                       ECDH_KEY_NAME,
                       pbPubKey,
                       dwPubKeyLen,
                       pbSecret,
                       &dwSecretLen,
                       0);
    if(nRet)
    {
        printf("Falha ao gerar ECDH RAW Secret.\n");
        goto CLEAN;
    }
    printf("Segredo ECDH RAW secret gerado com sucesso.\n");
    BYTE pbKDFData[] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18};
    GEN_ECDH_X9_63 stEcdhX963Info;
    memset(&stEcdhX963Info, 0, sizeof(stEcdhX963Info));
    strncpy(stEcdhX963Info.szTargetKeyName, ECDH_NEW_DERIVED_KEY, sizeof(stEcdhX963Info.szTargetKeyName));
    stEcdhX963Info.dwTargetKeyAlg = ALG_AES_256;
    stEcdhX963Info.dwTargetKeyAttributes = EXPORTABLE_KEY | TEMPORARY_KEY;
    stEcdhX963Info.dbPubKey.pvData = pbPubKey;
    stEcdhX963Info.dbPubKey.dwDataLen = dwPubKeyLen;
    stEcdhX963Info.dbKDFData.pvData = pbKDFData;
    stEcdhX963Info.dbKDFData.dwDataLen = sizeof(pbKDFData);
    
    nRet = DGenEcdhKey(hSession,
                       DN_GEN_KEY_X9_63_SHA256,
                       ECDH_KEY_NAME,
                       &stEcdhX963Info,
                       sizeof(stEcdhX963Info),
                       NULL,
                       NULL,
                       0);
    if(nRet)
    {
        printf("Falha ao gerar ECDH X9.63 Secret.\n");
        goto CLEAN;
    }
    printf("Chave ECDH X9.64 derivada com sucesso.\n");
   
    nRet = DRemoveObj(hSession, ECDH_NEW_DERIVED_KEY);
    if(nRet)
    {
        printf("Falha ao remover chave derivada.\n");
        goto CLEAN;
    }
    printf("Chave derivada removida com sucesso.\n");
CLEAN:
    DDestroyKey(&hKey, REMOVE_FROM_HSM);
    DDestroyKey(&hPairKey, REMOVE_FROM_HSM);
    printf("Contexto das chaves foram liberados.\n");
    DCloseSession(&hSession, 0);
    printf("Sessao encerrada.\n");
    DFinalize();
    printf("Bibliotecas finalizada.\n");
}