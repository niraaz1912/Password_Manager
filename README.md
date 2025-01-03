# Password Manager


## Registration

The program collects the username and password. A random 16-byte salt is generated. A derived key (password hash) is created using PBKDF2 with the salt. Username, password hash and the salt is stored in the database.

## Login

The program retrieves the stored password hash and salt of the given username. It derives a key from the entered password with the stored salt. If the derived key matches the stored hash, they are logged in.

## Security

If the database is compromised, they have access to: 

### User's Table

- #### Passsword Hash
    Derived from master password and random salt using PBKDF2. The hash is one-way.

- #### Salt
    Randomly generate 16-byte value to derive the hash. 

### Password's Table

- #### Encrypted Password
    Encrypted using AES-128-CFB with the encryption key (Password Hash) and random IV.

- #### IV (Initialization Vector)
    Uniquely generated values to encrypt the passwords.


## Can you derive Master Password?
The password hash and salt cannot alone reveal the master password. To derive the master password, the attacker will need to apply PBKDF2 using the salt, a candidate password and guess iteration count, which is the number of times the hashing algorithm was performed. This will generate a hash which they can compare with the stored one. 

*A strong password and high iteration count makes brute-forcing impractical.*

## Can you decrypt the Encrypted Passwords?
The ciphertext and IV is not sufficient to decrypt the passwords. To dercrypt the passwords, the attacker will need Encryption key and IV. However, the encryption key is derived from the user's master password. Without the master password, the attacker cannot decrypt the encrypted password.

