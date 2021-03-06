-module(xmerlsec_nif).

-export([keysmngr_create/0,
         keysmngr_destroy/1,
         keysmngr_add_key_and_cert/3,
         keysmngr_add_cert/2,
         sign/4, verify/4]).

-on_load(load/0).
-spec load() -> any().
load() ->
    PrivDir = case code:priv_dir(?MODULE) of
        {error, _} ->
            EbinDir = filename:dirname(code:which(?MODULE)),
            AppPath = filename:dirname(EbinDir),
            filename:join(AppPath, "priv");
        Path ->
            Path
    end,
    erlang:load_nif(filename:join(PrivDir, "xmerlsec_nif"), none).

keysmngr_create() ->
    throw({?MODULE, nif_not_loaded}).

keysmngr_destroy(_) ->
    throw({?MODULE, nif_not_loaded}).

keysmngr_add_key_and_cert(_,_,_) ->
    throw({?MODULE, nif_not_loaded}).

keysmngr_add_cert(_,_) ->
    throw({?MODULE, nif_not_loaded}).

sign(_, _, _, _) ->
    throw({?MODULE, nif_not_loaded}).

verify(_,_, _, _) ->
    throw({?MODULE, nif_not_loaded}).

