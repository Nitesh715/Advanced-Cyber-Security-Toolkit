from password_hash import(
    check_password_strength,
    generate_hash,
    verify_hash
)

#  Password test
password = "Cyber@123"

strength, suggestions = check_password_strength(password)

print("Password:", password)
print("Strength:", strength)

if suggestions:
    print("Suggestions:")
    for suggestion in suggestions:
        print("-", suggestion)

# Hash Test
text = "Hello Cyber Security"

hash_value = generate_hash(text, "sha256")

print("\nText:", text)
print("SHA-256:", hash_value)

# Verification test

result = verify_hash(
    text,
    hash_value,
    "sha256"
)
print("Hash Verification:", result)