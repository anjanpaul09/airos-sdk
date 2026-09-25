#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

static int hex_value(char c){
 if(c>='0'&&c<='9') return c-'0';
 if(c>='a'&&c<='f') return c-'a'+10;
 if(c>='A'&&c<='F') return c-'A'+10;
 return -1;
}

bool decrypt_aes(const char *hex,const char *b64,char *out,size_t outsz){
 EVP_CIPHER_CTX *ctx=NULL; unsigned char key[16]={0}, iv[16]={0}, decoded_key[32]={0}; unsigned char ciphertext[256], plain[272];
 size_t hexlen,i; int keylen=0,n=0,total=0; bool ok=false;
 if(!hex||!b64||!out||outsz<2) return false;
 out[0]='\0'; hexlen=strlen(hex);
 if(!hexlen||(hexlen&1)||(hexlen/2)>sizeof(ciphertext)||(hexlen/2)%16) goto done;
 for(i=0;i<hexlen;i+=2){ int hi=hex_value(hex[i]),lo=hex_value(hex[i+1]); if(hi<0||lo<0) goto done; ciphertext[i/2]=(unsigned char)((hi<<4)|lo); }
 { size_t b64len=strlen(b64), padding=0;
  if(!b64len||b64len%4) goto done;
  if(b64len>=1&&b64[b64len-1]=='=') padding++;
  if(b64len>=2&&b64[b64len-2]=='=') padding++;
  if(b64len > 24) goto done;
  keylen=EVP_DecodeBlock(decoded_key,(const unsigned char*)b64,(int)b64len);
  if(keylen<0) goto done;
  keylen-=(int)padding;
 }
 if(keylen!=16) goto done;
 memcpy(key,decoded_key,sizeof(key));
 memcpy(iv,key,16);
 ctx=EVP_CIPHER_CTX_new(); if(!ctx) goto done;
 if(EVP_DecryptInit_ex(ctx,EVP_aes_128_cbc(),NULL,key,iv)!=1) goto done;
 if(EVP_DecryptUpdate(ctx,plain,&n,ciphertext,(int)(hexlen/2))!=1) goto done;
 total=n;
 if(EVP_DecryptFinal_ex(ctx,plain+total,&n)!=1) goto done;
 total+=n;
 if(total<=0||(size_t)total>=outsz||memchr(plain,'\0',(size_t)total)) goto done;
 memcpy(out,plain,(size_t)total); out[total]='\0'; ok=true;
done:
 if(ctx) EVP_CIPHER_CTX_free(ctx);
 OPENSSL_cleanse(key,sizeof(key)); OPENSSL_cleanse(iv,sizeof(iv)); OPENSSL_cleanse(decoded_key,sizeof(decoded_key)); OPENSSL_cleanse(ciphertext,sizeof(ciphertext)); OPENSSL_cleanse(plain,sizeof(plain));
 if(!ok) out[0]='\0';
 return ok;
}
