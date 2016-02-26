-module(macaroon_log).
-behaviour(gen_server).

%% API.
-export([start_link/0]).
-export([add/4]).
-export([get_log/1]).
-export([stop/1]).

%% gen_server.
-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate/2]).
-export([code_change/3]).

-record(state, {
          log = []
}).

%% API.

-spec start_link() -> {ok, pid()}.
start_link() ->
	gen_server:start_link(?MODULE, [], []).


add(Caveat,Result,MoreInfo,Pid) when is_pid(Pid) ->
    gen_server:call(Pid,{add,Caveat,Result,MoreInfo});
add(_Caveat,_Result,_MoreInfo,_Pid) ->
    ok.

get_log(Pid) ->
    gen_server:call(Pid,get_log).

stop(Pid) ->
    gen_server:call(Pid,stop).
%% gen_server.

init([]) ->
	{ok, #state{}}.

handle_call({add,Caveat,Result,MoreInfo}, _From, #state{log=Log}=State) ->
    Entry = {Caveat,Result,MoreInfo},
    {reply, ok, State#state{log=[Entry|Log]}};
handle_call(get_log, _From, #state{log=Log}=State) ->
    {reply, {ok, lists:reverse(Log)}, State};
handle_call(stop, _From, State) ->
    {stop,normal,ok,State};
handle_call(_Request, _From, State) ->
	{reply, ignored, State}.

handle_cast(_Msg, State) ->
	{noreply, State}.

handle_info(_Info, State) ->
	{noreply, State}.

terminate(_Reason, _State) ->
	ok.

code_change(_OldVsn, State, _Extra) ->
	{ok, State}.
