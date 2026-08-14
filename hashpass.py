import bcrypt

# The password you want to use to sign in
password_to_hash = "123"

# Generate salt and hash
salt = bcrypt.gensalt()
hashed = bcrypt.hashpw(password_to_hash.encode('utf-8'), salt)

# Print this string to copy/paste into your database 'password_hash' column
print(hashed.decode('utf-8'))
