#!./venv/bin/python

import os
import contextlib
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
DEFAULT_FLAGS = lib.ARGON2_FLAG_CLEAR_PASSWORD | lib.ARGON2_FLAG_CLEAR_SECRET
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

    ARGON2_FLAGS = lib.ARGON2_FLAG_CLEAR_PASSWORD | lib.ARGON2_FLAG_CLEAR_SECRET

    def __init__(self,
        version=ARGON2_VERSION,
        secret=None,
        secrets=None, # An iterable of (keyid, key) tuples. The first key is used for new hashes.
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

        if secret:
            assert secrets is None, 'Can only specify either secret or secrets'
            secrets = [secret]
        if secrets:
            self.secret_map = dict(secrets)
            self.keyid = secrets[0][0]
            self.data = ffi.new("uint8_t[]", self.keyid)
            self.data_len = len(self.keyid)
            secret = secrets[0][1]
            self.csecret = ffi.new("uint8_t[]", secret)
            self.secret_len = len(secret)
        else:
            self.data = ffi.NULL
            self.data_len = 0
            self.csecret = ffi.NULL
            self.secret_len = 0


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
                ad=self.data, adlen=self.data_len,
                t_cost=self.t_cost,
                m_cost=self.m_cost,
                lanes=self.parallelism, threads=self.parallelism,
                allocate_cbk=ffi.NULL, free_cbk=ffi.NULL,
                flags=self.ARGON2_FLAGS,
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
        salt = _b64_decode_raw(match.group('salt'))
        raw_hash = _b64_decode_raw(match.group('hash'))
        t_cost = int(match.group('t_cost'))
        m_cost = int(match.group('m_cost'))
        parallelism = int(match.group('parallelism'))

        context_params = dict(
            time_cost=t_cost,
            memory_cost=m_cost,
            parallelism=parallelism,
            salt=salt,
            password=password,
        )

        keyid = match.group('keyid')
        if keyid:
            secret = self.secret_map.get(keyid)
            assert secret, 'No key for keyid %s' % keyid
            context_params['secret'] = secret
            context_params['data'] = keyid

        with argon2_context(**context_params) as ctx:
            result = lib.argon2i_verify_ctx(ctx, raw_hash)

        if result != lib.ARGON2_OK:
            raise VerifyMismatchError()


    def _encode(self, raw_hash, salt):
        format_args = dict(
            algo='argon2i',
            t_cost=self.t_cost,
            m_cost=self.m_cost,
            parallelism=self.parallelism,
            salt=base64.b64encode(salt).rstrip('='),
            hash=base64.b64encode(raw_hash).rstrip('='),
            version=self.version,
            keyid='',
        )
        if self.data:
            format_args['keyid'] = ',keyid={}'.format(self.keyid)
        return ('${algo}$v={version}$m={m_cost},t={t_cost},p={parallelism}{keyid}'
            '${salt}${hash}').format(**format_args)


def _b64_decode_raw(encoded):
    '''Decode basse64 string without padding'''
    return base64.b64decode(encoded + (b'='*((4 - len(encoded) % 4) % 4)))


@contextlib.contextmanager
def argon2_context(
        password=None,
        salt=None,
        secret=None,
        data=None,
        hash_len=DEFAULT_HASH_LENGTH,
        time_cost=DEFAULT_TIME_COST,
        memory_cost=DEFAULT_MEMORY_COST,
        parallelism=DEFAULT_PARALLELISM,
        flags=DEFAULT_FLAGS,
        ):
    csalt = ffi.new("uint8_t[]", salt)
    cout = ffi.new("uint8_t[]", hash_len)
    cpwd = ffi.new("uint8_t[]", password.encode('utf-8'))
    if secret:
        csecret = ffi.new("uint8_t[]", secret)
        secret_len = len(secret)
    else:
        csecret = ffi.NULL
        secret_len = 0
    if data:
        cdata = ffi.new("uint8_t[]", data)
        data_len = len(data)
    else:
        cdata = ffi.NULL
        data_len = 0
    ctx = ffi.new("argon2_context *", dict(
            version=ARGON2_VERSION,
            out=cout, outlen=hash_len,
            pwd=cpwd, pwdlen=len(password),
            salt=csalt, saltlen=len(salt),
            secret=csecret, secretlen=secret_len,
            ad=cdata, adlen=data_len,
            t_cost=time_cost,
            m_cost=memory_cost,
            lanes=parallelism, threads=parallelism,
            allocate_cbk=ffi.NULL, free_cbk=ffi.NULL,
            flags=DEFAULT_FLAGS,
        )
    )
    yield ctx


secret = ('1', 'supersecret')
secrets = [
    ('key1', 'actualsecretkey'),
    ('key2', 'othersecretkey'),
]

ph = PasswordHasher(secrets=secrets)

hashed = ph.hash('mypassword')
print(hashed)
print(ph.verify(hashed, 'mypassword'))
key2_hash = '$argon2i$v=19$m=512,t=2,p=2,keyid=key2$bSzaaXG0CVe3xPP7cykaSw$cZIoIsf7YI2Fdtv1v2hVvn+1oTuM1g0LIbCsPeU0v8c'
print(ph.verify(key2_hash, 'mypassword'))
