#include "database.h"
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>


int authenticate(sqlite3* db);
void setMasterKey(const string& key); // Set the global key for encryption
string decryptPassword(const string& ciphertext, const unsigned char* key, const unsigned char* iv);
string encryptPassword(const string& plaintext, const unsigned char* key, unsigned char* iv);
string getMasterKey();
int getUserId();