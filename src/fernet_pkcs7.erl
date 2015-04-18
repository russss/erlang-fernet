% This file is released under the MIT license.
% See the LICENSE file for more information.

-module(fernet_pkcs7).
-export([pad/1, pad/2, unpad/1]).
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-spec pad(binary()) -> binary().
pad(Data) ->
    pad(Data, 16).

-spec pad(binary(), byte()) -> binary().
pad(Data, Length) when is_binary(Data), is_integer(Length), byte_size(Data) < 256 ->
    Padding = case Length - byte_size(Data) rem Length of
        0 ->
            %% In case of no padding needed, add another full block
            Length;
        Other ->
            Other
    end,
    pad(Data, Padding, Padding).

-spec pad(binary(), byte(), byte()) -> binary().
pad(Data, _Padding, 0) ->
    Data;
pad(Data, Padding, Acc) ->
    D2 = pad(Data, Padding, Acc - 1),
    <<D2/binary, Padding/integer>>.

-spec unpad(binary()) -> binary().
unpad(Data) when is_binary(Data) ->
    Padding = binary:last(Data),
    unpad(Data, Padding, Padding).

-spec unpad(binary(), byte(), byte()) -> binary().
unpad(Data, _Value, 0) ->
    Data;
unpad(Data, Value, Count) ->
    case binary:last(Data) of
        Value ->
            ok;
        _ ->
            throw(invalid_padding)
    end,
    unpad(binary:part(Data, 0, byte_size(Data) - 1), Value, Count - 1).


-ifdef(TEST).
pad_test() ->
    <<3, 7, 7, 7, 7, 7, 7, 7>> = pad(<<3>>, 8),
    <<3, 3, 6, 6, 6, 6, 6, 6>> = pad(<<3, 3>>, 8),
    <<3, 3, 3, 5, 5, 5, 5, 5>> = pad(<<3, 3, 3>>, 8),
    <<3, 3, 3, 3, 4, 4, 4, 4>> = pad(<<3, 3, 3, 3>>, 8),
    <<3, 3, 3, 3, 3, 3, 3, 3>> = pad(<<3, 3, 3, 3, 3>>, 8),
    <<3, 3, 3, 3, 3, 3, 2, 2>> = pad(<<3, 3, 3, 3, 3, 3>>, 8),
    <<3, 3, 3, 3, 3, 3, 3, 1>> = pad(<<3, 3, 3, 3, 3, 3, 3>>, 8),
    <<3, 3, 3, 3, 3, 3, 3, 3, 8, 8, 8, 8, 8, 8, 8, 8>> = pad(<<3, 3, 3, 3, 3, 3, 3, 3>>, 8).

unpad_test() ->
    <<3>> = unpad(<<3, 7, 7, 7, 7, 7, 7, 7>>),
    <<3, 3>> = unpad(<<3, 3, 6, 6, 6, 6, 6, 6>>),
    <<3, 3, 3>> = unpad(<<3, 3, 3, 5, 5, 5, 5, 5>>),
    <<3, 3, 3, 3>> = unpad(<<3, 3, 3, 3, 4, 4, 4, 4>>),
    <<3, 3, 3, 3, 3>> = unpad(<<3, 3, 3, 3, 3, 3, 3, 3>>),
    <<3, 3, 3, 3, 3, 3>> = unpad(<<3, 3, 3, 3, 3, 3, 2, 2>>),
    <<3, 3, 3, 3, 3, 3, 3>> = unpad(<<3, 3, 3, 3, 3, 3, 3, 1>>),
    <<3, 3, 3, 3, 3, 3, 3, 3>> = unpad(<<3, 3, 3, 3, 3, 3, 3, 3, 8, 8, 8, 8, 8, 8, 8, 8>>),
    ?assertThrow(invalid_padding, unpad(<<3, 3, 6, 6, 6, 6, 6>>)).

-endif.
