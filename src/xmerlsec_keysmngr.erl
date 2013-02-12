-module(xmerlsec_keysmngr).
-export([create/0,destroy/1,add_key/2,add_cert/2]).

create() ->
    xmerlsec_nif:keysmngr_create().

destroy(KeysMngr) ->
    xmerlsec_nif:keysmngr_destroy(KeysMngr).

add_key(KeysMngr, KeyFile) ->
    xmerlsec_nif:keysmngr_add_key(KeysMngr,
                                  xmerlsec_util:coerce_c_string(KeyFile)).

add_cert(KeysMngr, CertFile) ->
    xmerlsec_nif:keysmngr_add_cert(KeysMngr,
                                   xmerlsec_util:coerce_c_string(CertFile)).
