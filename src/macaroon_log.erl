-module(macaroon_log).
-behaviour(gen_server).

%% API.
-export([start_link/0]).
-export([add_text/4]).
-export([begin_macaroon/2]).
-export([end_macaroon/1]).
-export([get_log/1]).
-export([get_raw_log/1]).
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

add_text(Format,Params,Result,Pid) when is_pid(Pid) ->
    Text = io_lib:format(Format,Params),
    gen_server:call(Pid,{add,Text,Result});
add_text(_Format,_Params, _Result, _Pid) ->
    ok.

get_log(Pid) ->
    gen_server:call(Pid,get_log).

get_raw_log(Pid) ->
    gen_server:call(Pid,get_raw_log).

begin_macaroon(MacaroonCid, Pid) when is_pid(Pid) ->
    gen_server:call(Pid,{begin_macaroon,MacaroonCid});
begin_macaroon(_MacaroonCid, _Pid)  ->
    ok.

end_macaroon(Pid) when is_pid(Pid) ->
    gen_server:call(Pid,end_macaroon);
end_macaroon(_Pid)  ->
    ok.

stop(Pid) ->
    gen_server:call(Pid,stop).
%% gen_server.

init([]) ->
	{ok, #state{}}.


handle_call({add,Description,Result}, _From, #state{log=Log}=State) ->
    Entry = {text, Description,Result},
    {reply, ok, State#state{log=[Entry|Log]}};
handle_call({begin_macaroon,Cid}, _From, #state{log=Log}=State) ->
    {reply, ok, State#state{log=[{begin_macaroon,Cid}|Log]}};
handle_call(end_macaroon, _From, #state{log=Log}=State) ->
    {reply, ok, State#state{log=[end_macaroon|Log]}};
handle_call(get_log, _From, #state{log=RawLog}=State) ->
    Log = convert_log(RawLog), 
    {reply, {ok, Log}, State};
handle_call(get_raw_log, _From, #state{log=Log}=State) ->
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


convert_log(RawLog) ->
    convert_log(lists:reverse(RawLog),0,0,[]).

convert_log([],_,_,Log) ->
    lists:reverse(Log);
convert_log([{text,Description,Result}|T],Level,OldNumber,Log) ->
    Number = OldNumber +1,
    Entry = {Number, add_indentation(Description, Level), Result},
    convert_log(T,Level,Number,[Entry | Log]);
convert_log([end_macaroon|T],OldLevel,OldNumber,Log) ->
    Level = OldLevel - 1,
    Number = OldNumber +1,
    Description = add_indentation(io_lib:format("Macarone DONE",[]),Level),
    Entry = {Number, Description , true},
    convert_log(T,Level,Number,[Entry | Log]);
convert_log([{begin_macaroon,Cid}|T],Level,OldNumber,Log) ->
    Number = OldNumber +1,
    Description = add_indentation(io_lib:format("Entering macaroon ~p",[Cid]),Level),
    Entry = {Number, Description , true},
    convert_log(T,Level+1,Number,[Entry | Log]).


add_indentation(Text,Level) when is_binary(Text) ->
    Indentation = get_indentation(Level),
    << Indentation/binary, Text/binary>>;
add_indentation(Text,Level) when is_list(Text) ->
    add_indentation(list_to_binary(Text),Level).
    

get_indentation(Number) when is_number(Number), Number > 0 ->
    get_indentation(Number,<<>>);
get_indentation(_Number) ->
    <<>>.

-define(INDENT,<<"   ">>).

get_indentation(0,Bin) ->
    Bin;
get_indentation(Num,Bin) ->
    get_indentation(Num-1, << ?INDENT/binary, Bin/binary >>).

