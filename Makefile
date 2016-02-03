PROJECT = macaroon

CT_SUITES = eunit

CT_OPTS = -cover test/cover.spec
CFLAGS =  -I/usr/include/sodium
LDFLAGS = -lsodium

DEPS = base64url
dep_base64url = git https://github.com/indigo-dc-tokentranslation/base64url.git master


include erlang.mk
