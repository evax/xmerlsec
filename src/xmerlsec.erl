%% @doc xmlsec signature and verification
-module(xmerlsec).
-include_lib("eunit/include/eunit.hrl").
-export([sign/4, verify/4]).

%% @doc Sign Element in Doc with the given key manager.
sign(Doc, Element, ElementNS, KeysMngr) ->
    xmerlsec_nif:sign(xmerlsec_util:coerce_c_string(Doc),
                      xmerlsec_util:coerce_c_string(Element),
                      xmerlsec_util:coerce_c_string(ElementNS),
                      KeysMngr).

%% @doc Verify Element in Doc with the given key manager.
verify(Doc, Element, ElementNS, KeysMngr) ->
    xmerlsec_nif:verify(xmerlsec_util:coerce_c_string(Doc),
                        xmerlsec_util:coerce_c_string(Element),
                        xmerlsec_util:coerce_c_string(ElementNS),
                        KeysMngr).

% Unit tests
xmerlsec_test() ->
    Path = filename:dirname(filename:dirname(?MODULE)),
    KeyPath = filename:join([Path, "..", "test", "key.pem"]),
    CertPath = filename:join([Path, "..", "test", "cert.pem"]),
    SrcPath = filename:join([Path, "..", "test", "test.xml"]),
    {ok, KeysMngr} = xmerlsec_keysmngr:create(),
    ok = xmerlsec_keysmngr:add_key_and_cert(KeysMngr, KeyPath, CertPath),
    {ok, File} = file:read_file(SrcPath),
    {ok, Signed} = xmerlsec:sign(File, "test", "http://test.com", KeysMngr),
    xmerlsec_keysmngr:destroy(KeysMngr),
    {ok, KeysMngr2} = xmerlsec_keysmngr:create(),
    ok = xmerlsec_keysmngr:add_cert(KeysMngr2, CertPath),
    {ok, true} = verify(Signed, "test", "http://test.com", KeysMngr2),
    xmerlsec_keysmngr:destroy(KeysMngr2).

