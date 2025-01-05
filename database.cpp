#include <iostream>
#include "database.h"

using namespace std;

sqlite3* initialize_database(sqlite3* db) {
    if (sqlite3_open("database.db", &db) != SQLITE_OK) {
        cerr << "Error opening database: " << sqlite3_errmsg(db) << endl;
        return nullptr;
    }

    const char* createUsersTable = R"(
        CREATE TABLE IF NOT EXISTS Users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            salt BLOB NOT NULL
        );
    )";

    const char* createPasswordsTable = R"(
        CREATE TABLE IF NOT EXISTS Passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            website TEXT NOT NULL,
            encrypted_password BLOB NOT NULL,
            iv BLOB NOT NULL,
            FOREIGN KEY (user_id) REFERENCES Users(id)
        );
    )";

    char* errorMessage = nullptr;
    if (sqlite3_exec(db, createUsersTable, nullptr, nullptr, &errorMessage) != SQLITE_OK) {
        cerr << "Error creating Users table: " << errorMessage << endl;
        sqlite3_free(errorMessage);
        return nullptr;
    }

    if (sqlite3_exec(db, createPasswordsTable, nullptr, nullptr, &errorMessage) != SQLITE_OK) {
        cerr << "Error creating Passwords table: " << errorMessage << endl;
        sqlite3_free(errorMessage);
        return nullptr;
    }

    return db;
}

bool registerUser(sqlite3* db, const string& username, const string& passwordHash, const string& salt) {
    const char* query = "INSERT INTO Users (username, password_hash, salt) VALUES (?, ?, ?);";
    sqlite3_stmt* stmt;

    // Prepare the SQL statement
    if (sqlite3_prepare(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        cerr << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        return false;
    }

    // Replace the ? placeholders with the actual values, SQLITE_STATIC tells that the bound values will not change
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, passwordHash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, salt.c_str(), salt.size(), SQLITE_STATIC);

    // Execute the statement and returns SQLITE_DONE if successful
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        cerr << "Error executing statement: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        return false;
    }

    // Release the prepared statement
    sqlite3_finalize(stmt);
    return true;
}

bool getUserCredentials(sqlite3* db, const string& username, string& passwordHash, string& salt, int& userId) {
    const char* query = "SELECT id, password_hash, salt FROM Users WHERE username = ?;";
    sqlite3_stmt* stmt;

    // Prepare the SQL statement
    if (sqlite3_prepare(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        cerr << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        return false;
    }

    // Replace the ? placeholder with the actual value
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

    // Execute the statement and returns SQLITE_ROW if a row is found (i.e., user exists)
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        userId = sqlite3_column_int(stmt, 0); // Get the user ID from the first column
        passwordHash = string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))); // Get the password hash from the second column as const char* then convert to string
        salt = string(reinterpret_cast<const char*>(sqlite3_column_blob(stmt, 2)), sqlite3_column_bytes(stmt, 2)); // Get the salt from the third column as binary blob, uses sqlite3_column_bytes to get the size and assigns to string
        sqlite3_finalize(stmt);
        return true;
    } else {
        cerr << "User not found." << endl;
        sqlite3_finalize(stmt);
        return false;
    }
}


bool storeWebsitePassword(sqlite3* db, const string& website, const string& password, const string& masterKey) {
    int userId = getUserId();
    if (userId == -1) {
        cerr << "User not logged in." << endl;
        return false;
    }

    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, sizeof(iv)); // Generate a random initialization vector
    string ivStr(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE); // Convert the IV to string for storage

    // Encrypt the password using the master key and IV
    string encryptedPassword = encryptPassword(password, reinterpret_cast<const unsigned char*>(masterKey.c_str()), iv);

    const char* query = "INSERT INTO Passwords (user_id, website, encrypted_password, iv) VALUES (?, ?, ?, ?);";
    sqlite3_stmt* stmt;

    // Prepare the SQL statement
    if (sqlite3_prepare(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        cerr << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        return false;
    }

    // Replace the ? placeholders with the actual values
    sqlite3_bind_int(stmt, 1, userId);
    sqlite3_bind_text(stmt, 2, website.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, encryptedPassword.c_str(), encryptedPassword.size(), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, ivStr.c_str(), ivStr.size(), SQLITE_STATIC);

    // Execute the statement and returns SQLITE_DONE if successful
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        cerr << "Error executing statement: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

string retrieveWebsitePassword(sqlite3* db, const string& website, const string& masterKey) {
    int userId = getUserId();
    if (userId == -1) {
        cerr << "User not logged in." << endl;
        return "";
    }

    const char* query = "SELECT encrypted_password, iv FROM Passwords WHERE website = ? AND user_id = ?;";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        cerr << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        return "";
    }

    sqlite3_bind_text(stmt, 1, website.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, userId);

    string encryptedPassword, ivStr;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        encryptedPassword = string(reinterpret_cast<const char*>(sqlite3_column_blob(stmt, 0)), sqlite3_column_bytes(stmt, 0));
        ivStr = string(reinterpret_cast<const char*>(sqlite3_column_blob(stmt, 1)), sqlite3_column_bytes(stmt, 1));
    } else {
        cerr << "Password not found for website: " << website << endl;
        sqlite3_finalize(stmt);
        return "";
    }

    sqlite3_finalize(stmt);

    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, ivStr.data(), AES_BLOCK_SIZE);

    return decryptPassword(encryptedPassword, reinterpret_cast<const unsigned char*>(masterKey.c_str()), iv);
}

void getWebsites(sqlite3* db){
    int userId = getUserId();
    if (userId == -1) {
        cerr << "User not logged in." << endl;
        exit(1);
    }

    const char* query = "SELECT website FROM Passwords WHERE user_id = ?;";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        cerr << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        exit(1);
    }

    sqlite3_bind_int(stmt, 1, userId);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* website = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        cout << website << endl;
    }

    sqlite3_finalize(stmt);
}
