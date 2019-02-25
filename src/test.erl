%%%-------------------------------------------------------------------
%%% @author admin
%%% @copyright (C) 2019, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 23. 二月 2019 10:07
%%%-------------------------------------------------------------------
-module(test).
-author("admin").

%% API
-export([test/0]).

test() ->
  C = eredis:start_link("172.20.58.1",6379,0),
  eredis:q(C,["HMGET",["mqconnect:login:151"|["pdSecret","status"]]]),
  io:format("hello").