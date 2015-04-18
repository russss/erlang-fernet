-module(fernet).
-export([generate_key/0,
         decrypt/2,
         decrypt/3,
         encrypt/2]).
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.
-define(MAX_CLOCK_SKEW, 60).

encode_token(Message, HMAC) ->
    base64url:encode(<<Message/bitstring, HMAC/bitstring>>).

decode_token(Token) ->
    TokenBin = base64url:decode(Token),
    %% Split the token into the HMAC and the message (everything else)
    HMAC = binary:part(TokenBin, byte_size(TokenBin), -256 div 8),
    Message = binary:part(TokenBin, 0, byte_size(TokenBin) - 256 div 8),
    {HMAC, Message}.

encode_message(Timestamp, IV, Ciphertext) ->
    <<128, Timestamp:64/integer, IV:128/bitstring, Ciphertext/binary>>.

decode_message(Message) ->
    <<128, Timestamp:64/integer, IV:128/bitstring, Ciphertext/binary>> = Message,
    {Timestamp, IV, Ciphertext}.

decode_key(Key) ->
    KeyBin = base64url:decode(Key),
    <<SigningKey:128/bitstring, EncryptionKey:128/bitstring>> = KeyBin,
    {SigningKey, EncryptionKey}.

generate_key() ->
    base64url:encode(crypto:strong_rand_bytes(256 div 8)).

decrypt(Token, Key) ->
    decrypt(Token, Key, none).

decrypt(Token, Key, TTL) ->
    decrypt(Token, Key, TTL, current_timestamp()).

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
    io:format("~w~n", [PaddedPlaintext]),
    try fernet_pkcs7:unpad(PaddedPlaintext) catch
        invalid_padding ->
            throw(invalid_token)
    end.

encrypt(Plaintext, Key) ->
    IV = crypto:strong_rand_bytes(128 div 8),
    Timestamp = current_timestamp(),
    encrypt(Plaintext, Key, IV, Timestamp).

encrypt(Plaintext, Key, IV, Timestamp) when is_binary(Plaintext), is_binary(IV), is_integer(Timestamp) ->
    {SigningKey, EncryptionKey} = decode_key(Key),
    PaddedPlaintext = fernet_pkcs7:pad(Plaintext),
    Ciphertext = crypto:block_encrypt(aes_cbc128, EncryptionKey, IV, PaddedPlaintext),
    Message = encode_message(Timestamp, IV, Ciphertext),
    HMAC = hmac_sha256(SigningKey, Message),
    encode_token(Message, HMAC).

hmac_sha256(Key, Data) ->
    crypto:hmac(sha256, Key, Data).

valid_hmac(HMAC, Data, Key) ->
    CalculatedHMAC = hmac_sha256(Key, Data),
    eq(CalculatedHMAC, HMAC).

valid_timestamp(_Timestamp, _CurrentTimestamp, TTL) when TTL == none ->
    true;
valid_timestamp(Timestamp, CurrentTimestamp, TTL) when Timestamp + TTL > CurrentTimestamp andalso
                                                       CurrentTimestamp + ?MAX_CLOCK_SKEW >= Timestamp ->
    true;
valid_timestamp(_Timestamp, _CurrentTimestamp, _TTL) ->
    false.

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
    {ok, Data} = file:read_file("../test_fixtures"),
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
