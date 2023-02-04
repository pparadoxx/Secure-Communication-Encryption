# What is this?

It's an encryption library. It's made to be as easy to implment and use as possible.

# So how do I implment it?

Well it's very easy actually. The calls are pretty simple.

# API: 

sce.Key() - Returns a generated key.

sce.Encrypt(string: encrypt, string: key) - Encrypts whatever is parsed in the first argument using the second argument.

sce.Decrypt(string: decrypt, string: key) - Decrypts whatever is parsed in the first argument using the second argument.

# INTERNAL:

sce.Hash(string: key) - Returns a hash of a key (INTERNAL; size limited to 1024, probably will fix in v2.1)

sce.HashTable(table: table) - Returns a hash of a tables values (INTERNAL; not used, meant as an API feature)

sce.HandleErrors() - Called when decryption fails at decrypting something instead of throwing an error (INTERNAL; meant to be an API feature but was never finished, probably will update in v2.1)

sce.ToASCII(table: table) - Called when encryption starts, returns a byted table (ASCII number; IE: 97 for lowercase a and 122 for z)
