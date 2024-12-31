# PasswordChecker
This program utilizes the HaveIBeenPwned API to check if your passwords have been involved in any data breaches.
It uses the k-anonymity model to ensure that your entire password is never sent to the API, making it theoretically
more secure than using the actual website.

###HOW IT WORKS

## 1. Password Hashing
    a. The input password is hashed using the SHA-1 algorithm
    b. The hash is split into two parts: the first 5 chars (prefix) and the remaining 35 (suffix)

## 2. API Request:
    a. The program sends the prefix to the HIBP API.
    b. The API responds with a list of all hash suffixes that match the given prefix, along with a count of how many
        times each has appeared in data breaches

## 3. Hash Matching:
    a. The program checks if the suffix of your hashed password matches any of the returned suffixes from the API
    b. If a match is found, the associated breach count is displayed
