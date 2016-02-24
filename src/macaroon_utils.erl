-module(macaroon_utils). 

-export([
         serialize_kv_list/1,
         parse_kv/1,
         parse_kv/2,
         inspect_kv_list/1,
         bin_to_hex/1,
         hex_to_bin/1
        ]).


-define(KEYMAPPING,[
                    {identifier,<<"identifier">>},
                    {location,<<"location">>},
                    {signature,<<"signature">>},
                    {cid,<<"cid">>},
                    {vid,<<"vid">>},
                    {cl,<<"cl">>}
                   ]).

-define(PACKET_PREFIX,4).

kv_to_bin(_AtomKey,undefined) ->
    <<>>;
kv_to_bin(AtomKey,Value) ->
    Key = map_to_binary_key(AtomKey),
	ByteLength = byte_size(Key) + byte_size(Value) + ?PACKET_PREFIX + 2,
	HexLen = list_to_binary(io_lib:format("~4.16.0b",[ByteLength])),
	Space = <<" ">>,
	NL = <<"\n">>,
	<<HexLen/binary,Key/binary,Space/binary,Value/binary,NL/binary>>.

serialize_kv_list(List) ->
    serialize_kv_list(List,<<>>).

serialize_kv_list([],Binary) ->
    base64url:encode(Binary);
serialize_kv_list([{K,V}|T],Binary) ->
    KVBin = kv_to_bin(K,V),
    NewBinary = << Binary/binary, KVBin/binary >>,
    serialize_kv_list(T,NewBinary).
    

map_to_binary_key(Key) when is_binary(Key) ->
    Key;
map_to_binary_key(AtomKey) ->
    {AtomKey, Key} = lists:keyfind(AtomKey,1,?KEYMAPPING),
    Key.

map_to_atom_key(Key,_) when is_atom(Key) ->
    Key;
map_to_atom_key(BinKey,false) ->
    BinKey;
map_to_atom_key(BinKey,_) ->
    {Key, BinKey} = lists:keyfind(BinKey,2,?KEYMAPPING),
    Key.

parse_kv(Data) ->
    parse_kv(Data,false).

parse_kv(Data,MapToAtom) ->
    parse_kv(Data,[],MapToAtom).
                        
parse_kv(<<>>,KVList,_MapToAtom) ->
    {ok,lists:reverse(KVList)};
parse_kv(Data,KVList,MapToAtom) ->
    case parse_single_kv(Data,MapToAtom) of
        {ok,KV,NewData} ->
            parse_kv(NewData,[KV|KVList],MapToAtom);
        {error,_} = E -> E
    end.
    

parse_single_kv(Data,MapToBin) ->
	case byte_size(Data) >= ?PACKET_PREFIX of 
		true ->
			<<LengthEnc:?PACKET_PREFIX/binary,Rest/binary>> = Data,
			<<LengthA:16/unsigned>> = hex_to_bin(binary:bin_to_list(LengthEnc)),
			Length = LengthA - ?PACKET_PREFIX,
			case byte_size(Rest) >= Length of
				true -> 
					<<Enc:Length/binary,DataLeft/binary>> = Rest,
					[BinKey,Val] = binary:split(Enc,[<<" ">>],[trim]),
                    Key = map_to_atom_key(BinKey,MapToBin),
                    SList = binary:split(Val,[<<"\n">>],[trim,{scope,{byte_size(Val),-1}}]),
                    Value = case SList of 
                                [V] -> V;
                                [] -> <<>>
                            end,
                    
					{ok,{Key,Value},DataLeft};
				false ->
					{error,not_enough_data}
			end;
		false ->
			{error,not_enough_data}
	end.

inspect_kv_list(List) ->
    inspect_kv_list(List,<<>>).

inspect_kv_list([],Binary) ->
    Binary;
inspect_kv_list([{K,V}|Tail],Binary) ->
    KvBin = kv_inspect(K,V),
    NewBinary = << Binary/binary, KvBin/binary >>,
    inspect_kv_list(Tail,NewBinary).

kv_inspect(_,undefined) ->
    <<>>;
kv_inspect(signature = AKey,Val) ->
    Key = map_to_binary_key(AKey),
    Value = bin_to_hex(Val),
    kv_inspect_line(Key,Value);
kv_inspect(vid = AKey,Val) ->
    Key = map_to_binary_key(AKey),
    Value = base64url:encode(Val),
    kv_inspect_line(Key,Value);
kv_inspect(AKey,Value) ->
    Key = map_to_binary_key(AKey),
    kv_inspect_line(Key,Value).


kv_inspect_line(Key,Value) ->
	<<Key/binary,<<" ">>/binary,Value/binary,<<"\n">>/binary>>.


bin_to_hex(Data) ->
	bin_to_hex(Data,<<>>).

bin_to_hex(<<>>,Hex) ->
	Hex;
bin_to_hex(<<C:8,Rest/binary>>,Hex) ->
	CHex = list_to_binary(io_lib:format("~2.16.0b",[C])),
	bin_to_hex(Rest,<< Hex/binary, CHex/binary >>).

hex_to_bin(BinaryHex) when is_binary(BinaryHex) ->
    hex_to_bin(binary_to_list(BinaryHex));
hex_to_bin(Str) -> << << (erlang:list_to_integer([H], 16)):4 >> || H <- Str >>.
