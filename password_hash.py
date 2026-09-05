import hashlib
import re

# =========================
# Password Strength Checker
# =========================

def check_password_strength(password):

    score = 0
    suggestions = []

    if len(password) >= 8:
        score += 1
    else:
        suggestions.append("Use at least 8 character.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
         suggestions.append("Add at least one Uppercase letter.")
    if re.search(r"[a-z]", password):
        score += 1
    else:
        suggestions.append("Add at least one lower letter.")

    if  re.search(r"[0-9]", password):
        score += 1

    else:
        suggestions.append("Add at least one number.")

    if  re.search(r"[A-za-z0-9]", password):
        score += 1

    else:
        suggestions.append("Add at least one special character.")

    if score <=2:
        strength = "Weak"
    elif score <=4:
        strength = "Medium"
    else :
        strength = "Strong"

    return strength, suggestions

# =======================
# Hash Generator
# =======================

def generate_hash(text, algorithm="sha256"):

    text_bytes = text.encode("utf-8")

    if algorithm.lower() == "md5":
        return hashlib.md5(text_bytes).hexdigest()

    elif algorithm.lower() =="sha1":
        return hashlib.sha1(text_bytes).hexdigest()

    elif algorithm.lower() =="sha256":
        return hashlib.sha256(text_bytes).hexdigest()

    elif algorithm.lower() =="sha512":
        return hashlib.sha512(text_bytes).hexdigest()

    else:
        raise ValueError("Unsupported hash algorithm")

# =======================
# Hash Verification
#========================

def verify_hash(text, expected_hash, algorithm="sha256"):

    generated_hash = generate_hash(text, algorithm)

    return generated_hash.lower() == expected_hash.lower()