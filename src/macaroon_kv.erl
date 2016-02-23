-module(macaroon_kv).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.
-export([
	create/2,
	parse/1,
	get_type/1,
	get_value/1,
	set_value/2,
	inspect/1,
	get_bin_rep/1,
    as_map/1
	]).

-record(kv, {
		key = none,
		value = none,
		bin_rep = <<>>
		}).

-define(PACKET_PREFIX,4).


-spec create(Key::atom(), Value::binary()) -> #kv{}.
create(AKey,Value) ->
	Key = case AKey of 
		location -> <<"location">>;
		identifier -> <<"identifier">>;
		signature -> <<"signature">>;
		cid -> <<"cid">>;
		vid -> <<"vid">>;
		cl -> <<"cl">>
	end,
	BinRep = to_bin_rep(Key,Value),
	#kv{key=Key,value=Value,bin_rep=BinRep}.

parse(Data) ->
	case byte_size(Data) >= ?PACKET_PREFIX of 
		true ->
			<<LengthEnc:?PACKET_PREFIX/binary,Rest/binary>> = Data,
			<<LengthA:16/unsigned>> = hex_to_bin(binary:bin_to_list(LengthEnc)),
			Length = LengthA - ?PACKET_PREFIX,
			case byte_size(Rest) >= Length of
				true -> 
					<<Enc:Length/binary,Return/binary>> = Rest,
					[Key,Val] = binary:split(Enc,[<<" ">>],[trim]),
                    SList = binary:split(Val,[<<"\n">>],[trim,{scope,{byte_size(Val),-1}}]),
                    Value = case SList of 
                                [V] -> V;
                                [] -> <<>>
                            end,
					{#kv{key=Key,value=Value,bin_rep=to_bin_rep(Key,Value)},Return};
				false ->
					{error,not_enough_data}
			end;
		false ->
			{error,not_enough_data}
	end.

get_type(#kv{key=Key}) ->
	case Key of
		<<"location">> -> location;
		<<"identifier">> -> identifier;
		<<"signature">> -> signature;
		<<"cid">> -> cid;
		<<"vid">> -> vid;
		<<"cl">> -> cl;
        _ -> Key
	end.


get_value(#kv{value=Val}) ->
	Val.

set_value(Value,#kv{key=Key}=Kv) ->
	Kv#kv{value=Value,bin_rep=to_bin_rep(Key,Value)}.

inspect(#kv{key=Key,value=Val}) ->
	Value = case Key of 
		<<"signature">> -> bin_to_hex(Val);
		<<"vid">> -> base64url:encode(Val);
		_ -> Val
	end,
	<<Key/binary,<<": ">>/binary,Value/binary,<<"\n">>/binary>>.

as_map(#kv{value=Val} = KV) ->
    Key = get_type(KV),
	Value = case Key of 
		signature -> bin_to_hex(Val);
		vid -> base64url:encode(Val);
		_ -> Val
	end,
   #{Key => Value}.

get_bin_rep(#kv{bin_rep=BinRep}) ->
	BinRep.


to_bin_rep(Key,Value) ->
	ByteLength = byte_size(Key) + byte_size(Value) + ?PACKET_PREFIX + 2,
	HexLen = list_to_binary(io_lib:format("~4.16.0b",[ByteLength])),
	Space = <<" ">>,
	NL = <<"\n">>,
	<<HexLen/binary,Key/binary,Space/binary,Value/binary,NL/binary>>.

hex_to_bin(Str) -> << << (erlang:list_to_integer([H], 16)):4 >> || H <- Str >>.

bin_to_hex(Data) ->
	bin_to_hex(Data,<<>>).

bin_to_hex(<<>>,Hex) ->
	Hex;
bin_to_hex(<<C:8,Rest/binary>>,Hex) ->
	CHex = list_to_binary(io_lib:format("~2.16.0b",[C])),
	bin_to_hex(Rest,<< Hex/binary, CHex/binary >>).

-ifdef(TEST).

parse_test() ->
	{error,_} = parse(<<"3f2">>),
	{error,_} = parse(<<"000f ">>).

-endif.
