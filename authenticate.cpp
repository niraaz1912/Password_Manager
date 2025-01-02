#include <iostream>
#include "authenticate.h"

string globalMasterKey;

void setMasterKey(const string& key) {
    globalMasterKey = key;
}

string getMasterKey(){
    return globalMasterKey;
}

int globalUserId = -1;

void setUserId(int userId) {
    globalUserId = userId;
}

int getUserId() {
    return globalUserId;
}


string encryptPassword(const string& plaintext, const unsigned char* key, unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw runtime_error("Failed to create encryption context");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize encryption");
    }

    string ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_128_cfb()), '\0');
    int len = 0;

    if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &len,
                          reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Encryption failed");
    }

    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]) + len, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Final encryption step failed");
    }

    ciphertext.resize(len + finalLen);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

string decryptPassword(const string& ciphertext, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw runtime_error("Failed to create decryption context");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize decryption");
    }

    string plaintext(ciphertext.size(), '\0');
    int len = 0;

    if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]), &len,
                          reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Decryption failed");
    }

    int finalLen = 0;
    if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]) + len, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Final decryption step failed");
    }

    plaintext.resize(len + finalLen);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

string deriveKey(const string& password, const unsigned char* salt, int keyLength = 16, int iterations = 100000) {
    unsigned char key[EVP_MAX_KEY_LENGTH];
    if (!PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.size(), salt, 16, iterations, keyLength, key)) {
        throw runtime_error("Key derivation failed.");
    }
    return string(reinterpret_cast<char*>(key), keyLength);
}

int authenticate(sqlite3* db) {
    cout << "Press 1 to register, 2 to log in: ";
    int choice;
    cin >> choice;

    cout << "Enter your username: ";
    string username;
    cin >> username;

    cout << "Enter your master password: ";
    string masterPassword;
    cin >> masterPassword;

    if (choice == 1) {
        // Registration
        unsigned char salt[16];
        RAND_bytes(salt, sizeof(salt));
        string saltStr(reinterpret_cast<char*>(salt), sizeof(salt));

        string hashedPassword = deriveKey(masterPassword, salt);

        if (registerUser(db, username, hashedPassword, saltStr)) {
            cout << "Registration successful!" << endl;
            return 1;
        } else {
            cerr << "Registration failed. User may already exist." << endl;
            return 3;
        }
    } else if (choice == 2) {
        // Login
        string storedHash, storedSalt;
        int userId = -1;
        if (!getUserCredentials(db, username, storedHash, storedSalt, userId)) {
            cerr << "User not found." << endl;
            return 3;
        }

        unsigned char salt[16];
        memcpy(salt, storedSalt.c_str(), sizeof(salt));
        string derivedHash = deriveKey(masterPassword, salt);

        if (derivedHash == storedHash) {
            cout << "Login successful!" << endl;
            setMasterKey(masterPassword);
            setUserId(userId);
            return 2;
        } else {
            cerr << "Incorrect password." << endl;
            return 3;
        }
    } else {
        cerr << "Invalid choice." << endl;
        return 3;
    }
}
