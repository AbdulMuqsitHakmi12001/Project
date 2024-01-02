import getpass


class RBACSystem:
    def __init__(self):
        self.users = {}
        self.roles = {}
        self.user_file = "users.txt"
        self.role_file = "roles.txt"
        self.load_roles_from_file()
        self.load_users_from_file()
        

    def encrypt(self,text, shift):
        encrypted_text = ""
        for char in text:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                encrypted_char = chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
                encrypted_text += encrypted_char
            else:
                encrypted_text += char
        return encrypted_text
    
    def decrypt(self,text, shift):
         return self.encrypt(text, -shift)
     

    def load_roles_from_file(self):
        try:
            with open(self.role_file, 'r') as file:
                role_lines = file.readlines()
                self.roles = {}
                for line in role_lines:
                    parts = line.strip().split(":")
                    if len(parts) == 2:
                        role, permissions = parts
                        self.roles[role] = set(permissions.split(','))
                    else:
                        print(f"Warning: Ignoring invalid line in role file: {line}")
        except FileNotFoundError:
            print("Role file not found. Creating a new one.")

    def save_roles_to_file(self):
        with open(self.role_file, 'w') as file:
            file.write('\n'.join(f"{role}:{','.join(permissions)}" for role, permissions in self.roles.items()))

    def load_users_from_file(self):
        try:
            with open(self.user_file, 'r') as file:
                user_lines = file.readlines()
                self.users = {}
                for line in user_lines:
                    parts = line.strip().split(":")
                    if len(parts) == 2:
                        username, role = parts
                        self.users[username] = role
                    else:
                        print(f"Warning: Ignoring invalid line in user file: {line}")
        except FileNotFoundError:
            print("User file not found. Creating a new one.")

    def save_users_to_file(self):
        with open(self.user_file, 'w') as file:
            file.write('\n'.join(f"{user}:{role}" for user, role in self.users.items()))
  
   
    def create_user(self, username, role,user_role):
        if role not in self.roles:
            print(f"Error: Role '{role}' does not exist.")
            return

        if user_role != "boss":
            print("Error: You don't have access to add users.")
            return
        
        usernameE= self.encrypt(username, shift=3)
        roleE= self.encrypt(role, shift=3)

        self.users[usernameE] = roleE
        
        self.save_users_to_file()
        print(f"User '{ username}' created with role '{role}'.")

    def remove_user(self,username,role):
        usernameE= self.encrypt(username, shift=3)
        if usernameE in self.users:
            if self.users[usernameE] == "boss":
                print("Error: Boss cannot be removed.")
                return
            if role != "boss":
             print("Error: You don't have access to remove users.")
             return
    
            
            del self.users[usernameE]
            self.save_users_to_file()
            print(f"User '{username}' removed.")
        else:
            print(f"Error: User '{username}' does not exist.")

    def edit_username(self, old_username, new_username, current_role):
        old_usernameT=old_username
        old_username = self.encrypt(old_username, shift=3)
        new_usernameT=new_username
        new_username = self.encrypt(new_username, shift=3)
        if old_username in self.users:
            if current_role != "useradmin" and current_role != "boss":
                print("Error: You don't have access to edit usernames.")
                return
            role = self.users.pop(old_username)
            self.users[new_username] = role
            self.save_users_to_file()
            print(f"Username '{old_usernameT}' changed to '{new_usernameT}'.")
        else:
            print(f"Error: User '{old_username}' does not exist.")

    def add_role(self, role, permissions, current_role):
        if current_role == "role_admin" or current_role == "boss":
                self.roles[role] = set(permissions)
                self.save_roles_to_file()
                print(f"Role '{role}' created with permissions: {permissions}")


        else:
            print("Error: You don't have access to add roles.")
        
    def remove_role(self, role, current_role):
        if role in self.roles:
            if current_role == "role_admin" or current_role == "boss":
                del self.roles[role]
           
                for user, user_role in list(self.users.items()):
                    if user_role == role:
                        del self.users[user]
                self.save_roles_to_file()
                self.save_users_to_file()
                print(f"Role '{role}' removed.")
            else:
                print(f"Error: Role '{role}' does not exist.")

            
        else:
            print(f"Error: Role '{role}' does not exist.")

    def assign_role(self, username, role):
        if username not in self.users:
            print(f"Error: User '{username}' does not exist.")
            return

        if role not in self.roles:
            print(f"Error: Role '{role}' does not exist.")
            return

        self.users[username] = role
        self.save_users_to_file()
        print(f"User '{username}' assigned to role '{role}'.")

    def check_permission(self, username, permission):
        if username not in self.users:
            print(f"Error: User '{username}' does not exist.")
            return False

        role = self.users[username]
        if role not in self.roles:
            print(f"Error: Role '{role}' does not exist.")
            return False

        if permission not in self.roles[role]:
            print(f"Error: Permission '{permission}' not granted to user '{username}'.")
            return False

        print(f"Access granted: User '{username}' has permission '{permission}'.")
        return True

    def view_users(self):
        print("==== Users ====")
        for user, role in self.users.items():
            userD = self.decrypt(user, shift=3)  
            roleD = self.decrypt(role, shift=3)  
            print(f"{userD}: {roleD}")

    def view_roles(self):
        print("==== Roles ====")
        for role, permissions in self.roles.items():
            print(f"{role}: {','.join(permissions)}")


def authenticate(rbac_system):
    print("===== User Authentication =====")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    flag=0


    try:
        with open("credentials.txt", 'r') as file:
            credentials = [line.strip().split(":") for line in file.readlines()]
            for user, encrypted_passwd in credentials:
                decrypted_passwd = rbac_system.decrypt(encrypted_passwd, shift=3)  # Use Caesar Cipher with a shift of 3
                if user == username and decrypted_passwd == password:
                    flag=1
                    print(f"Authentication successful. Welcome, {username}!")
                    return username
        
            if flag==0:
             print("Authentication failed. Invalid username or password.")
            return None 
    except FileNotFoundError:
        print("Error: Credentials file not found.")
        return None, None
    
def findRole(username,rbac_system):
    encrypted_username = rbac_system.encrypt(username, shift=3)
    with open("users.txt", 'r') as file:
            credentials = [line.strip().split(":") for line in file.readlines()]
            for user, role in credentials:
                if user == encrypted_username:
                    return rbac_system.decrypt(role,3)
            return None


def print_menu(username,role):
    print("\n===== RBAC System =====")
    print(f"Logged in as: ---{username}--- with role of **{role}**")
    print("1. Add User")
    print("2. Remove User")
    print("3. Add Role")
    print("4. Remove Role")
    print("5. Assign Role")
    print("6. Check User Permission")
    print("7. View Users")
    print("8. View Roles")
    print("9. EditUsername")
    print("10. Exit")




def main():
    rbac_system = RBACSystem()
    username= authenticate(rbac_system)
    

    if username is None:
        return
    role = findRole(username,rbac_system)

    while True:
        print_menu(username,role)

        choice = input("Enter your choice (1-10): ")

        if choice == "1":
            new_username = input("Enter new username: ")
            new_role = input("Enter role: ")
            rbac_system.create_user(new_username, new_role,role)
        elif choice == "2":
            usernameR = input("Enter username of the user you want to remove: ")
            rbac_system.remove_user(usernameR, role,)
        elif choice == "3":
            new_role = input("Enter new role: ")
            new_permissions = input("Enter permissions (comma-separated): ").split(',')
            rbac_system.add_role(new_role, new_permissions, role)
        elif choice == "4":
            remove_role = input("Enter role to remove: ")
            rbac_system.remove_role(remove_role, role)
        elif choice == "5":
            assign_username = input("Enter username to assign role: ")
            assign_role = input("Enter role to assign: ")
            rbac_system.assign_role(assign_username, assign_role, role)
        elif choice == "6":
            check_username = input("Enter username to check permission: ")
            check_permission = input("Enter permission to check: ")
            rbac_system.check_permission(check_username, check_permission)
        elif choice == "7":
            rbac_system.view_users()
        elif choice == "8":
            rbac_system.view_roles()
        elif choice == "9":
            edit_username = input("Enter username to edit: ")
            new_username = input("Enter new username: ")
            rbac_system.edit_username(edit_username, new_username, role)
        elif choice == "10":
             print("Exiting RBAC System. Goodbye!")
             break
            
       
        else:
            print("Invalid choice. Please enter a number between 1 and 10.")

if __name__ == "__main__":
    main()