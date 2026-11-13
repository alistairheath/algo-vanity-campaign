from algosdk import account, mnemonic
import time

# Desired prefix for address.
PREFIX = "ALGOX"

# Variables containing Private Key and Address
PRIVATE_KEY = ""
ADDRESS = ""

# Keep track of attempts and start time.
ATTEMPT = 0
SMALL_MATCHES = 0
TIME_START = time.time()

# Keep looping until desired address is found.
while (not ADDRESS.startswith(PREFIX)):
    TIME_DIFF = time.time() - TIME_START
    if TIME_DIFF == 0:
        TIME_DIFF = 1  # Prevent division by zero
    print(f" {ATTEMPT} ({ATTEMPT / TIME_DIFF:.2f}/sec)", end="\r")
    PRIVATE_KEY, ADDRESS = account.generate_account()
    ATTEMPT += 1


# Display your new address, private key, and mnemonic
print()
print(f"Found after {ATTEMPT} attempts and {TIME_DIFF:.2f} seconds")
print(ADDRESS)
print(PRIVATE_KEY)
print(mnemonic.from_private_key(PRIVATE_KEY))
print()