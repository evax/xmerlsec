-module(xmerlsec_util).
-export([coerce_c_string/1]).

coerce_c_string(S) when is_atom(S) ->
    coerce_c_string(atom_to_list(S));
coerce_c_string(S) when is_list(S) ->
    coerce_c_string(list_to_binary(S));
coerce_c_string(S) ->
    case binary:last(S) of
        0 -> S;
        _ -> <<S/binary, 0>>
    end.
