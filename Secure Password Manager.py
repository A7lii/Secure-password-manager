import os
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

settings_file = os.path.join(BASE_DIR, "settings.json")
if not os.path.exists(settings_file):
    settings_file = os.path.join(BASE_DIR, "settings.example.json")

passwords_file = os.path.join(BASE_DIR, "passwords.json")
if not os.path.exists(passwords_file):
    passwords_file = os.path.join(BASE_DIR, "passwords.example.json")



#haslib is used for hashing passwords securely
import hashlib
# getpass is used to securely input passwords without showing them on the screen
import getpass
# json to save and load passwords from a file
import json
#  os to check if the password file exists
import os
# re checks strength of password
import re
# secrets to generate secure random passwords
import secrets
# time to add delay for security and lockout for security
import time


# load user data from a file if it exists
def load_data():
    if os.path.exists("passwords.json"):
        with open("passwords.json", "r") as file:
            return json.load(file)
    return {}
# loads saved users
def save_users(users):
    with open("passwords.json", "w") as file:
        json.dump(users, file)
    
# random salt maker
def generate_salt():
    return secrets.token_hex(32)

# hash password with salt
def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode()).hexdigest()

# password strength checker
def check_password_strength(password):
    if len(password) < 8: 
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, "Password is strong."

        
# password manager is a storage for hashed passwords
password_manager = load_data()

# ask whether to show the password as it is typed
def prompt_password(prompt):
    while True:
        choice = input("\nShow password while typing? (y/n): ").strip().lower()
        if choice == "y":
            return input(prompt)
        if choice == "n":
            return getpass.getpass(prompt)
        print("Please enter 'y' or 'n'.")




# def = define a function
def create_account():
    username = input("\nEnter a new username (or 'b' to go back): ").strip()
    if username.lower() in ("b", "back"):
        print("\nReturning to main menu.")
        return
    if username in password_manager:
        print("\nUsername already exists. Please choose a different username.")
        return
    if not username:
        print("\nUsername cannot be empty.")
        return
    
    password = prompt_password("\nEnter a new password (or 'b' to go back): ")
    if password.lower() in ("b", "back"):
        print("\nReturning to main menu.")
        return
    ok, message = check_password_strength(password)
    if not ok:
        print("\nWeak password:", message)
        return
        # haslib.sha256 is used to hash the password
    # hexdigest() converts the hash object to a hexadecimal string so it can be read
    Salt = generate_salt()
    password_manager[username] = {
        'salt': Salt,   
        'hashed_password': hash_password(password, Salt)
    }
    save_users(users=password_manager)
    print("\n Account created successfully!")
  # saves the new user data
def login(users, password_manager, state):
    # lockout check
    now = time.time()
    if now < state['lockout_time']:
        left = int(state['lockout_time'] - now)
        print(f"Account is locked. Try again in {left} seconds.")
        return False

    username = input("\nEnter your username (or 'b' to go back): ").strip()
    if username.lower() in ("b", "back"):
        print("\nReturning to main menu.")
        return False

    password = prompt_password("\nEnter your password (or 'b' to go back): ")
    if password.lower() in ("b", "back"):
        print("\nReturning to main menu.")
        return False

    if username not in password_manager:
        print("\nLogin failed. Incorrect username or password.")
        state['attempts'] += 1
    else:
        salt = password_manager[username]['salt']
        hashed_password = hash_password(password, salt)
        if hashed_password != password_manager[username]['hashed_password']:
            print("\nLogin failed. Incorrect username or password.")
            state['attempts'] += 1
        else:
            print("\nLogin successful!")
            state['attempts'] = 0  # reset attempts on successful login
            state['lockout_time'] = 0
            return True

    # lockout mechanism                              
    if state['attempts'] >= 3:
        state['lockout_time'] = now + 30  # lockout for 30 seconds
        print("Too many failed attempts. Account is locked for 30 seconds.")
    return False

# def main controls the whole program flow (what the user will be seeing and doing)
def main():
    users = load_data()
    state = {"attempts": 0, "lockout_time": 0}
    while True:
        choice = input("\nEnter 1 to create an account, 2 to login, or 3 to exit: ")
        if choice == '1':
            create_account()
        elif choice == '2':
            login(users, password_manager, state)
        elif choice == '3':
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please try again.")




# makes sure the main function runs when the script is executed
if __name__ == "__main__":
    main()
