#!./venv/bin/python

import os
import base64
import re

import argon2.low_level
from argon2 import PasswordHasher
from argon2.low_level import ARGON2_VERSION, Type, core, ffi, lib
from argon2.exceptions import VerifyMismatchError

DEFAULT_SALT_LENGTH = 16
DEFAULT_HASH_LENGTH = 32
DEFAULT_TIME_COST = 2
DEFAULT_MEMORY_COST = 512
DEFAULT_PARALLELISM = 2
# This regex validats the spec from
# https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
ENCODED_HASH_RE = re.compile(r'^\$' + r'\$'.join([
    # TODO: Validate max lengths of fields
        r'argon2i',
        r'v=(?P<version>[0-9]+)',
        #                                                                     optional group with keyid=<keyid>    optional group with data=<data>
        r'm=(?P<m_cost>[0-9]+),t=(?P<t_cost>[0-9]+),p=(?P<parallelism>[0-9]+)(?:,keyid=(?P<keyid>[a-zA-Z0-9+/]+))?(,data=(?P<data>[a-zA-Z0-9+/]+))?',
        r'(?P<salt>[a-zA-Z0-9+/]+)',
        r'(?P<hash>[a-zA-Z0-9+/]+)',
    ]) + r'$'
)


class PasswordHasher(object):

    def __init__(self,
        version=ARGON2_VERSION,
        secret=None,
        time_cost=DEFAULT_TIME_COST,
        memory_cost=DEFAULT_MEMORY_COST,
        parallelism=DEFAULT_PARALLELISM,
        hash_len=DEFAULT_HASH_LENGTH,
        salt_len=DEFAULT_SALT_LENGTH,
    ):
        # Make sure you keep FFI objects alive until *after* the core call!
        self.version = version
        self.t_cost = time_cost
        self.m_cost = memory_cost
        self.parallelism = parallelism
        self.hash_len = hash_len
        self.salt_len = salt_len
        self.csecret = ffi.new("uint8_t[]", secret) if secret is not None else ffi.NULL
        self.secret_len = len(secret) if secret else 0


    def hash(self, password):
        cout = ffi.new("uint8_t[]", self.hash_len)
        cpwd = ffi.new("uint8_t[]", password.encode('utf-8'))
        salt = os.urandom(self.salt_len)
        csalt = ffi.new("uint8_t[]", salt)
        ctx = ffi.new("argon2_context *", dict(
                version=ARGON2_VERSION,
                out=cout, outlen=self.hash_len,
                pwd=cpwd, pwdlen=len(password),
                salt=csalt, saltlen=self.salt_len,
                secret=self.csecret, secretlen=self.secret_len,
                ad=ffi.NULL, adlen=0,
                t_cost=self.t_cost,
                m_cost=self.m_cost,
                lanes=self.parallelism, threads=self.parallelism,
                allocate_cbk=ffi.NULL, free_cbk=ffi.NULL,
                flags=lib.ARGON2_DEFAULT_FLAGS,
            )
        )
        result = core(ctx, Type.I.value)
        assert result == lib.ARGON2_OK
        raw_hash = bytes(ffi.buffer(ctx.out, ctx.outlen))
        return self._encode(raw_hash, salt)


    def verify(self, hashed, password):
        assert len(hashed) < 1024 # Ensure we don't DDoS ourselves if the database holds corrupt values
        # TODO: Ensure hashed values are maximum double of what we're configured with
        # TODO: Test migrating parameters
        match = ENCODED_HASH_RE.match(hashed)
        assert match, 'Hashed string is on unknown format'
        version = int(match.group('version'))
        assert version == ARGON2_VERSION, 'Unknown version of hashed password'
        cout = ffi.new("uint8_t[]", self.hash_len)
        cpwd = ffi.new("uint8_t[]", password.encode('utf-8'))
        salt = _b64_decode_raw(match.group('salt'))
        raw_hash = _b64_decode_raw(match.group('hash'))
        csalt = ffi.new("uint8_t[]", salt)
        t_cost = int(match.group('t_cost'))
        m_cost = int(match.group('m_cost'))
        parallelism = int(match.group('parallelism'))
        ctx = ffi.new("argon2_context *", dict(
                version=ARGON2_VERSION,
                out=cout, outlen=len(raw_hash),
                pwd=cpwd, pwdlen=len(password),
                salt=csalt, saltlen=len(salt),
                secret=self.csecret, secretlen=self.secret_len,
                ad=ffi.NULL, adlen=0,
                t_cost=t_cost,
                m_cost=m_cost,
                lanes=parallelism, threads=parallelism,
                allocate_cbk=ffi.NULL, free_cbk=ffi.NULL,
                flags=lib.ARGON2_DEFAULT_FLAGS,
            )
        )
        result = lib.argon2i_verify_ctx(ctx, raw_hash)
        if result != lib.ARGON2_OK:
            raise VerifyMismatchError()


    def _encode(self, raw_hash, salt):
        return '${algo}$v={version}$m={m_cost},t={t_cost},p={parallelism}${salt}${hash}'.format(
            algo='argon2i',
            t_cost=self.t_cost,
            m_cost=self.m_cost,
            parallelism=self.parallelism,
            salt=base64.b64encode(salt).rstrip('='),
            hash=base64.b64encode(raw_hash).rstrip('='),
            version=self.version,
        )

def _b64_decode_raw(encoded):
    '''Decode basse64 string without padding'''
    return base64.b64decode(encoded + (b'='*((4 - len(encoded) % 4) % 4)))


secret = b'supersecret'

ph = PasswordHasher(secret=secret)

hashed = ph.hash('mypassword')
print(hashed)
print(ph.verify(hashed, 'mypassword'))
