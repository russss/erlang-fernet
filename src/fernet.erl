% This file is released under the MIT license.
% See the LICENSE file for more information.

-module(fernet).
-export([generate_key/0,
         decrypt/2,
         decrypt/3,
         encrypt/2]).
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.
-define(MAX_CLOCK_SKEW, 60).

-type token() :: [binary() | string()].
-type key() :: [binary() | string()].
-type hmac() :: <<_:128>>.
-type timestamp() :: integer().
-type ttl() :: integer() | none.
-type iv() :: <<_:128>>.

-spec encode_token(binary(), binary()) -> binary().
encode_token(Message, HMAC) when is_binary(Message), is_binary(HMAC) ->
    base64url:encode(<<Message/bitstring, HMAC/bitstring>>).

-spec decode_token(token()) -> {hmac(), binary()}.
decode_token(Token) ->
    TokenBin = base64url:decode(Token),
    %% Split the token into the HMAC and the message (everything else)
    HMAC = binary:part(TokenBin, byte_size(TokenBin), -256 div 8),
    Message = binary:part(TokenBin, 0, byte_size(TokenBin) - 256 div 8),
    {HMAC, Message}.

-spec encode_message(timestamp(), iv(), binary()) -> binary().
encode_message(Timestamp, IV, Ciphertext) ->
    <<128, Timestamp:64/integer, IV:128/bitstring, Ciphertext/binary>>.

-spec decode_message(binary()) -> {timestamp(), iv(), binary()}.
decode_message(Message) ->
    <<128, Timestamp:64/integer, IV:128/bitstring, Ciphertext/binary>> = Message,
    {Timestamp, IV, Ciphertext}.

-spec decode_key(token()) -> {binary(), binary()}.
decode_key(Key) ->
    KeyBin = base64url:decode(Key),
    <<SigningKey:128/bitstring, EncryptionKey:128/bitstring>> = KeyBin,
    {SigningKey, EncryptionKey}.

-spec generate_key() -> binary().
generate_key() ->
    base64url:encode(crypto:strong_rand_bytes(256 div 8)).

-spec decrypt(token(), key()) -> binary().
decrypt(Token, Key) ->
    decrypt(Token, Key, none).

-spec decrypt(token(), key(), ttl()) -> binary().
decrypt(Token, Key, TTL) ->
    decrypt(Token, Key, TTL, current_timestamp()).

-spec decrypt(token(), key(), ttl(), timestamp()) -> binary().
decrypt(Token, Key, TTL, CurrentTimestamp) ->
    {HMAC, Message} = try decode_token(Token) catch
        error:_ -> throw(invalid_token)
    end,
    {Timestamp, IV, Ciphertext} = try decode_message(Message) catch
        error:{badmatch, _} -> throw(invalid_token)
    end,
    {SigningKey, EncryptionKey} = decode_key(Key),
    case valid_timestamp(Timestamp, CurrentTimestamp, TTL) andalso valid_hmac(HMAC, Message, SigningKey) of
        false ->
            throw(invalid_token);
        true ->
            valid
    end,
    PaddedPlaintext = try crypto:block_decrypt(aes_cbc128, EncryptionKey, IV, Ciphertext) catch
        error:_ -> throw(invalid_token)
    end,
    try fernet_pkcs7:unpad(PaddedPlaintext) catch
        invalid_padding ->
            throw(invalid_token)
    end.

-spec encrypt(binary(), key()) -> binary().
encrypt(Plaintext, Key) ->
    IV = crypto:strong_rand_bytes(128 div 8),
    Timestamp = current_timestamp(),
    encrypt(Plaintext, Key, IV, Timestamp).

-spec encrypt(binary(), key(), iv(), timestamp()) -> binary().
encrypt(Plaintext, Key, IV, Timestamp) when is_binary(Plaintext), is_binary(IV), is_integer(Timestamp) ->
    {SigningKey, EncryptionKey} = decode_key(Key),
    PaddedPlaintext = fernet_pkcs7:pad(Plaintext),
    Ciphertext = crypto:block_encrypt(aes_cbc128, EncryptionKey, IV, PaddedPlaintext),
    Message = encode_message(Timestamp, IV, Ciphertext),
    HMAC = hmac_sha256(SigningKey, Message),
    encode_token(Message, HMAC).

-spec hmac_sha256(binary(), binary()) -> binary().
hmac_sha256(Key, Data) ->
    crypto:hmac(sha256, Key, Data).

%-spec valid_hmac(hmac(), binary(), binary()) -> binary().
valid_hmac(HMAC, Data, Key) ->
    CalculatedHMAC = hmac_sha256(Key, Data),
    eq(CalculatedHMAC, HMAC).

-spec valid_timestamp(timestamp(), timestamp(), ttl()) -> boolean().
valid_timestamp(_Timestamp, _CurrentTimestamp, TTL) when TTL == none ->
    true;
valid_timestamp(Timestamp, CurrentTimestamp, TTL) when Timestamp + TTL > CurrentTimestamp andalso
                                                       CurrentTimestamp + ?MAX_CLOCK_SKEW >= Timestamp ->
    true;
valid_timestamp(_Timestamp, _CurrentTimestamp, _TTL) ->
    false.

-spec current_timestamp() -> timestamp().
current_timestamp() ->
    {Mega, Sec, Micro} = os:timestamp(),
    Mega * 1000000 * 1000000 + Sec * 1000000 + Micro.

%% Constant-time equality check, from Mochiweb's mochiweb_session module (BSD license).
-spec eq(binary(), binary()) -> boolean().
eq(A, B) when is_binary(A) andalso is_binary(B) ->
    eq(A, B, 0).

eq(<<A, As/binary>>, <<B, Bs/binary>>, Acc) ->
    eq(As, Bs, Acc bor (A bxor B));
eq(<<>>, <<>>, 0) ->
    true;
eq(_As, _Bs, _Acc) ->
    false.


-ifdef(TEST).
generate_key_test() ->
    decode_key(generate_key()).

roundtrip_test() ->
    Key = generate_key(),
    Plaintext = <<"Test message 1234567890123456789012345678901234567890">>,
    Token = encrypt(Plaintext, Key),
    Plaintext = decrypt(Token, Key).

fernet_spec_test() ->
    {ok, Data} = file:read_file(code:priv_dir(fernet) ++ "/test_fixtures"),
    [run_tests(Type, Tests) || {Type, Tests} <- erlang:binary_to_term(Data)].

run_tests("verify", Tests) ->
    [spec_verify(Test) || Test <- Tests];
run_tests("invalid", Tests) ->
    [spec_invalid(Test) || Test <- Tests];
run_tests("generate", Tests) ->
    [spec_generate(Test) || Test <- Tests].

spec_verify(Test) ->
    Src = list_to_binary(proplists:get_value("src", Test)),
    Src = decrypt(proplists:get_value("token", Test), proplists:get_value("secret", Test),
                  proplists:get_value("ttl_sec", Test), proplists:get_value("now", Test)).

spec_invalid(Test) ->
    Token = proplists:get_value("token", Test),
    Secret = proplists:get_value("secret", Test),
    TTL = proplists:get_value("ttl_sec", Test),
    Now = proplists:get_value("now", Test),
    ?assertThrow(invalid_token, decrypt(Token, Secret, TTL, Now)).

spec_generate(Test) ->
    Token = list_to_binary(proplists:get_value("token", Test)),
    Secret = proplists:get_value("secret", Test),
    Now = proplists:get_value("now", Test),
    IV = list_to_binary(proplists:get_value("iv", Test)),
    Src = list_to_binary(proplists:get_value("src", Test)),
    Token = encrypt(Src, Secret, IV, Now).

-endif.
