%%--------------------------------------------------------------------
%% Copyright (c) 2013-2018 EMQ Enterprise, Inc. (http://emqtt.io)
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%--------------------------------------------------------------------

-module(emq_auth_redis).

-behaviour(emqttd_auth_mod).

-include("emq_auth_redis.hrl").

-include_lib("emqttd/include/emqttd.hrl").

-export([init/1, check/3, description/0,load/1,unload/0]).

-define(UNDEFINED(S), (S =:= undefined)).

-record(state, {auth_cmd, super_cmd, hash_type}).

init({AuthCmd, SuperCmd, HashType}) ->
  io:format("init"),
  {ok, #state{auth_cmd = AuthCmd, super_cmd = SuperCmd, hash_type = HashType}}.

check(#mqtt_client{username = Username}, Password, _State)
  when ?UNDEFINED(Username); ?UNDEFINED(Password) ->
  {error, username_or_password_undefined};

check(Client, Password, #state{auth_cmd  = AuthCmd,
  super_cmd = SuperCmd,
  hash_type = HashType}) ->


  try
    check_userName(Client,Password,HashType)
  catch
    error:{Caught, {Error, X}} ->
      io:format(binary_to_list(X))
  end.

q(Cmd) ->

  case ecpool:with_client(?APP, fun(C) -> eredis:q(C, Cmd) end) of
    {ok,[]} -> fail;
    {ok,[undefined]} ->fail;
    {ok,[undefined,undefined]} ->fail;
    {ok,Result} -> {ok,Result};
    {error,Reason} ->{error,Reason}
  end.

check_userName(#mqtt_client{client_id= ClientId,username = Username},Password,HashType) ->
  io:format("~n->compare (:)"),
  Usernames = binary_to_list(Username),
  case string:str(Usernames,":")>0 of
    true ->
      %%有冒号走这一步
      io:format("~n->has colon(:),start login"),
      case q(["HGETALL",string:concat("mqconnect:login:",ClientId)]) of
        fail -> io:format("~n->DidResult is null"),fail ;
        {error,Reason} ->{error,Reason};
        {ok,_} -> case q(["HMGET",string:concat("mqconnect:login:",ClientId)|["pdSecret","status"]]) of
                    fail -> io:format("~n->password and status is null"),fail ;
                    {error,Reason} ->{error,Reason};

                    {ok,[P,S]} ->
                      io:format(string:concat("~n->P=",binary_to_list(P))),
                      io:format(string:concat("~n->S=",binary_to_list(S))),
                      %%这里执行判断密码是否通过
                      case check_pass(P, Password, HashType) of
                        ok ->
                          %%判断status
                          case string:equal(binary_to_list(S),"0") of
                            true -> case q(["HMSET",string:concat("mqconnect:login:",ClientId)|[ "status","1"]]) of
                                      {error,Reason} ->{error,Reason};
                                      fail ->fail ;
                                      {ok,_} -> io:format("~n->updated status"),ok
                                    end;
                            false -> io:format("~n-> status != 0 ,login fail "),fail
                          end
                      end
                  end
      end;
    false ->
      %%没有冒号，userName中不存在did，开始注册
      io:format("->no colon(:) ,start register"),
      io:format(string:concat("~n->productKey = ", Usernames)),

      case q(["HGETALL",string:concat("mqconnect:register:",Usernames)]) of
        fail ->io:format("~n->productKey is undefined"),fail;
        {error,Reason} ->{error,Reason};

        {ok,_} -> case q(["HMGET",string:concat("mqconnect:register:",Usernames)|["productSecret"]]) of
                    fail -> io:format("~n->did is undefined"),fail;
                    {error,Reason} ->{error,Reason};

                    {ok,[P]} ->
                      io:format(string:concat("~n->P=",binary_to_list(P))),
                      %%这里执行判断密码是否通过
                      case check_pass(P, Password, HashType) of
                        ok ->
                          %%判断status
                          DidResult = q(["HGETALL",string:concat("mqconnect:login:",ClientId)]),
                          case DidResult of
                            fail -> io:format("~n->ClientId key is undefined"),fail;
                            {error,Reason} ->{error,Reason};
                            {ok,_} -> case q(["HMGET",string:concat("mqconnect:login:",ClientId)|["status"]]) of
                                        fail -> io:format("~n->status is undefined"),fail ;
                                        {error,Reason} ->{error,Reason};
                                        {ok,[S]} ->
                                          io:format(string:concat("~n->S=",binary_to_list(S))),
                                          %%这里执行判断密码是否通过
                                          %%判断status
                                          case string:equal(binary_to_list(S),"0") of
                                            true -> case q(["HMSET",string:concat("mqconnect:login:",ClientId)|[ "status","2"]]) of
                                                      fail -> fail ;
                                                      {error,Reason} ->{error,Reason};
                                                      {ok,_} -> io:format("~n->updated status "),ok
                                                    end;
                                            false -> io:format("~n-> status != 0 ,register fail "),fail
                                          end
                                      end
                          end
                      end
                  end
      end
  end.

check_pass(PassHash, Password, HashType) ->
  check_pass(PassHash, hash(HashType, Password)).
check_pass(PassHash, Salt, Password, {pbkdf2, Macfun, Iterations, Dklen}) ->
  check_pass(PassHash, hash(pbkdf2, {Salt, Password, Macfun, Iterations, Dklen}));
check_pass(PassHash, Salt, Password, {salt, bcrypt}) ->
  check_pass(PassHash, hash(bcrypt, {Salt, Password}));
check_pass(PassHash, Salt, Password, {salt, HashType}) ->
  check_pass(PassHash, hash(HashType, <<Salt/binary, Password/binary>>));
check_pass(PassHash, Salt, Password, {HashType, salt}) ->
  check_pass(PassHash, hash(HashType, <<Password/binary, Salt/binary>>)).

check_pass(PassHash, PassHash) -> ok;
check_pass(_, _)               -> {error, password_error}.

description() -> "Authentication with Redis".

hash(Type, Password) -> emqttd_auth_mod:passwd_hash(Type, Password).

-spec(is_superuser(undefined | list(), mqtt_client()) -> boolean()).
is_superuser(undefined, _Client) ->
  false;
is_superuser(SuperCmd, Client) ->
  case emq_auth_redis_cli:q(SuperCmd, Client) of
    {ok, undefined} -> false;
    {ok, <<"1">>}   -> true;
    {ok, _Other}    -> false;
    {error, _Error} -> false
  end.

%%emq钩子的使用
load(Env) ->
  emqx:hook('client.disconnected', fun ?MODULE:on_client_disconnected/3, [Env]).
unload() ->
  emqx:unhook('client.disconnected', fun ?MODULE:on_client_disconnected/3).
on_client_disconnected(#{client_id := ClientId}, ReasonCode, _Env) ->
  io:format("Client(~s) disconnected, reason_code: ~w~n", [ClientId, ReasonCode]).
