#define BOOL unsigned char
#define BYTE unsigned char
void des0(BOOL bEncrypt, BYTE* lpSrc, BYTE* lpKey, BYTE* lpResult);
void des0_ex(BOOL bEncrypt, BYTE* lpSrc, BYTE* KeyBlock, BYTE* lpResult);
void dtob(BYTE Data, BYTE* lpResult);
void des_algo(BYTE* lpSrc, BYTE* lpDest, BYTE* lpKey, BOOL bEncrypt);
void des_algo_ex(BYTE* lpSrc, BYTE* lpDest, BYTE* KeyBlock, BOOL bEncrypt);
void Transfer(BYTE* lpSrc, BYTE* lpDest, BYTE* lpTable);
void KeyGenerate(BYTE* lpKeyIn, BYTE* lpKeySub, int nCount);
void KeyGenerate_ex(BYTE* KeyBlock, BYTE* lpKeySub, int nCount);
void Circle(BYTE* lpBuf, int nLength);
void S_change(BYTE* lpBuf);
void str_xor(BYTE* lpSrc, BYTE* lpDest, int nLen);
void str_cpy(BYTE* lpSrc, BYTE* lpDest, int nLen);
