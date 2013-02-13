-module(xmerlsec_keysmngr).
-export([create/0,destroy/1,add_key_and_cert/3,add_cert/2]).

create() ->
    xmerlsec_nif:keysmngr_create().

destroy(KeysMngr) ->
    xmerlsec_nif:keysmngr_destroy(KeysMngr).

add_key_and_cert(KeysMngr, KeyFile, CertFile) ->
    xmerlsec_nif:keysmngr_add_key_and_cert(
                    KeysMngr,
                    xmerlsec_util:coerce_c_string(KeyFile),
                    xmerlsec_util:coerce_c_string(CertFile)).

add_cert(KeysMngr, CertFile) ->
    xmerlsec_nif:keysmngr_add_cert(KeysMngr,
                                   xmerlsec_util:coerce_c_string(CertFile)).
