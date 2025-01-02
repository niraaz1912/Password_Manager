#include "database.h"
#include "authenticate.h"
#include <iostream>

using namespace std;

int main(int argc, char* argv[]) {
    sqlite3* db = initialize_database(nullptr);
    if (!db) {
        cerr << "Database initialization failed." << endl;
        return 1;
    }

    int authStatus = authenticate(db);
    if (authStatus == 2) {  // Login successful
        int choice;
        do {
            cout << "\n1. Store a website password\n2. View stored passwords\n3. Exit\nChoose an option: ";
            cin >> choice;

            if (choice == 1) {
                string website, password;
                cout << "Enter website: ";
                cin >> website;
                cout << "Enter password: ";
                cin >> password;
                if (storeWebsitePassword(db, website, password, getMasterKey())) {
                    cout << "Password stored successfully!" << endl;
                } else {
                    cerr << "Failed to store the password." << endl;
                }
            } else if (choice == 2) {
                getWebsites(db);
                string website;
                cout << "Enter website: ";
                cin >> website;
                string password = retrieveWebsitePassword(db, website, getMasterKey());
                if (!password.empty()) {
                    cout << "Password for " << website << ": " << password << endl;
                } else {
                    cerr << "Password not found." << endl;
                }
            }
        } while (choice != 3);
    } else if (authStatus == 1) {  // Registration successful
        cout << "Registration successful! Please log in to proceed." << endl;
    } else {
        cerr << "Authentication failed." << endl;
    }

    sqlite3_close(db);
    return 0;
}
