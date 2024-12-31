import requests
import hashlib

# Params query_char: first 5 characters of hashed password
# Returns res: response object
#
# This function sends a request to the PwnedPasswords API using the k-anonymity model.
# Only the first 5 characters of the hashed password are sent to the API, ensuring privacy.
# The API responds with all hash suffixes that match the provided prefix, along with breach counts.
def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check api and try again')
    return res

# Params hashes: response object, hash_to_check: tail of hashed password
# Returns count: number of times password was found in data breaches
#
# This function parses the response from the PwnedPasswords API. It splits each line of the response
# into a hash suffix and its associated count, then checks if the hash_to_check matches any of the suffixes.
def get_pwd_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


# Params password: password to check
# Returns count: number of times password was found in data breaches
#
# This function converts the input password into a SHA-1 hash and splits the hash into two parts:
# the first 5 characters (prefix) and the remaining 35 characters (tail). The prefix is sent to
# the PwnedPasswords API, and the tail is used to find the exact match from the API response.
def pwned_api_check(password):
    sha1pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1pwd[:5], sha1pwd[5:]
    response = request_api_data(first5_char)
    return get_pwd_leaks_count(response, tail)

# Main function to provide an interactive menu for checking passwords against the PwnedPasswords API
#
# The user is presented with a menu where they can choose to either enter a password to check or quit the program.
# If the user chooses to check a password, the program will determine if the password has been involved in any data breaches
# and display the appropriate message.
def main():
    print("This tool will let you know if any of your passwords have been involved in data breaches.")
    while True:
        print("\nSelect an option below:")
        print("1: Enter password to check")
        print("2: Quit")

        choice = input("Enter your choice (1 or 2): ").strip()

        if choice == '1':
            password = input("Enter the password to check: ").strip()
            count = pwned_api_check(password)
            if count:
                print(f'\n"{password}" was found {count} times... you should change your password.')
            else:
                print(f'\n"{password}" was NOT found. Carry on!')
        elif choice == '2':
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please select 1 or 2.")


if __name__ == "__main__":
    main()