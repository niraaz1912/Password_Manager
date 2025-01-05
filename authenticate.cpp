#include <iostream>
#include "authenticate.h"

// Holds User's masterkey for use in encryption and decryption. -1 indicates no user is logged in
string globalMasterKey;
int globalUserId = -1;

// Sets the global master key after sucessful login
void setMasterKey(const string& key) {
    globalMasterKey = key;
}

// Retrives global master key
string getMasterKey(){
    return globalMasterKey;
}

// Sets global user ID after login
void setUserId(int userId) {
    globalUserId = userId;
}

// Retrieves global user ID
int getUserId() {
    return globalUserId;
}

/* Encrypts a plain password using AES-128-CFB encyption
plaintext: The password to encrypt
key: The encryption key derived from the master key
iv: The initialization vector for encryption
*/ 
string encryptPassword(const string& plaintext, const unsigned char* key, unsigned char* iv) {
    // Allocate memory for encryption context which manages all encryption operations
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw runtime_error("Failed to create encryption context");
    }

    // Initializes the context for AES-128-CFB encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), nullptr, key, iv) != 1) { // 0: failure, 1: success
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize encryption");
    }

    // Allocate memory for the ciphertext. 
    string ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_128_cfb()), '\0'); // EVP_CIPHER_block_size() returns the block size for encryption algo. (16 for AES)
    int len = 0;

    // Encrypts the plain text and writes the cipher text to the buffer. len is updated with the number of bytes written
    if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &len,
                          reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size()) != 1) { // EVP_EncryptUpdate() encrypts the data in chunks and updates the output buffer
                          // reinterpret_cast is used to convert char* to unsigned char* because EVP functions require unsigned char*
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Encryption failed");
    }

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

/* Decrypts an encrypted password back into plain text
ciphertext: The encrypted password
key: The decryption key (same as encryption key)
iv: The initialization vector used during encryption
*/
string decryptPassword(const string& ciphertext, const unsigned char* key, const unsigned char* iv) {
    // Allocate memory for decryption context which manages all decryption operations
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw runtime_error("Failed to create decryption context");
    }

    // Initializes the context for AES-128-CFB decryption. Sets the encryption key and IV
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Failed to initialize decryption");
    }

    // Allocate memory for the plaintext. 
    string plaintext(ciphertext.size(), '\0');
    int len = 0;

    // Decrypts the cipher text (ciphertext.c_str) and writes the plain text to the buffer. len is updated with the number of bytes written
    if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]), &len,
                          reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size()) != 1) { // EVP_DecryptUpdate() decrypts the data in chunks and updates the output buffer
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Decryption failed");
    }

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

/* Derives an encryption key from the user's master password and a salt using PBKDF2
password: The master password
salt: A 16-byte salt for key derivation
*/
string deriveKey(const string& password, const unsigned char* salt) {
    int keyLength = 16; // 16 bytes for AES-128
    int iterations = 100000; // Number of iterations for PBKDF2
    unsigned char key[EVP_MAX_KEY_LENGTH];
    if (!PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.size(), salt, 16, iterations, keyLength, key)) { // Implements PBKDF2 using HMAC-SHA1 hash function. c_str() is used to convert string to char*
        throw runtime_error("Key derivation failed.");
    }
    return string(reinterpret_cast<char*>(key), keyLength);
}

// Handles user registration and login
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
        RAND_bytes(salt, sizeof(salt)); // Generate a random 16-byte salt
        string saltStr(reinterpret_cast<char*>(salt), sizeof(salt)); // Convert salt to string for storage

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
