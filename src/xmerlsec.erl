%% Copyright (C) 2013 Evax Software <contact@evax.fr>
%%
%% Permission is hereby granted, free of charge, to any person obtaining a copy
%% of this software and associated documentation files (the "Software"), to deal
%% in the Software without restriction, including without limitation the rights
%% to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
%% copies of the Software, and to permit persons to whom the Software is
%% furnished to do so, subject to the following conditions:
%%
%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
%% OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
%% THE SOFTWARE.
%%
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

