-module(xmerlsec).
-export([sign/2, verify/2]).


sign(Doc, KeysMngr) ->
    xmerlsec_nif:sign(xmerlsec_util:coerce_c_string(Doc), KeysMngr).

verify(Doc, KeysMngr) ->
    xmerlsec_nif:verify(xmerlsec_util:coerce_c_string(Doc), KeysMngr).

