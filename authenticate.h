#ifndef AUTHENTICATE_H
#define AUTHENTICATE_H

#include "database.h"
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

using namespace std;

int authenticate(sqlite3* db);
void setMasterKey(const string& key); // Set the global key for encryption
string decryptPassword(const string& ciphertext, const unsigned char* key, const unsigned char* iv);
string encryptPassword(const string& plaintext, const unsigned char* key, unsigned char* iv);
string getMasterKey();
int getUserId();
string deriveKey(const string& password, const unsigned char* salt);

#endif // AUTHENTICATE_H