#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>
#include <string>
#include <cstring>
#include "authenticate.h"

using namespace std;

sqlite3* initialize_database(sqlite3* db);
bool registerUser(sqlite3* db, const string& username, const string& passwordHash, const string& salt);
bool getUserCredentials(sqlite3* db, const string& username, string& passwordHash, string& salt, int& userId);
string retrieveWebsitePassword(sqlite3* db, const string& website, const string& masterKey);
bool storeWebsitePassword(sqlite3* db, const string& website, const string& password, const string& masterKey);
void getWebsites(sqlite3* db);

#endif // DATABASE_H