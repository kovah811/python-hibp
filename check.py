"""Simple CLI utility to check if a password is found in the HIBP DB

This tool utilizes the SHA1 prefix range method of checking passwords from the
HIBP DB. This means only the first 5 characters of the checked password's SHA1
hash are sent to HIBP's API.

See https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/ for
an explanation of the k-Anonymity approach this utility is leveraging.

"""

import argparse
import gc
import urllib.request
import urllib.parse

from getpass import getpass
from hashlib import sha1


API_URL = 'https://api.pwnedpasswords.com/range/{}'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('password', nargs='?',
            help='(Optional) The password to be checked. If not specified, '
                 'password can be provided interactively')
    args = parser.parse_args()

    if args.password:
        pwhash = sha1(args.password.encode()).hexdigest().upper()
    else:
        pwhash = sha1(getpass('Password to check: ')
                      .encode()).hexdigest().upper()

    prefix = pwhash[:5]
    # Keep the suffix in bytes since that's what we get back from HIBP
    suffix = pwhash[5:].encode()

    # Make it a *little* bit more difficult to sniff things out of memory...
    args.password = None
    pwhash = None
    gc.collect()

    # User-Agent is specified to work around restrictions on Python
    req = urllib.request.Request(API_URL.format(prefix),
                                 headers={'User-Agent': 'Mozilla/5.0'})
    hashes = urllib.request.urlopen(req).read().splitlines()

    num = None
    for h in hashes:
        if suffix in h:
            # Each suffix is also returned with a number of occurences
            num = h.split(b':')[1].decode()

    if num:
        print('Password found in HIBP DB; appears {} times.'.format(num))
    else:
        print('Password not found in HIBP DB!')


if __name__ == '__main__':
    main()
