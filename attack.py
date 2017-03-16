#!./venv/bin/python

import argparse

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# These are all terrible, terrible passwords, NEVER construct a password this
# short and simple
candidates = (
    'password123',
    'sesamsesam',
    'mypassword',
    'hunter2',
)

ph = PasswordHasher()


def main():
    args = get_args()
    for candidate in candidates:
        try:
            ph.verify(args.hash, candidate)
        except VerifyMismatchError:
            pass
        else:
            print('Found password: %s' % candidate)
            break
    else:
        print('No password found')


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('hash')
    return parser.parse_args()


if __name__ == '__main__':
    main()
