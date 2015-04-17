-module(fernet).
-export([generate_key/0,
         decrypt/2,
         decrypt/3,
         encrypt/2]).
-include_lib("eunit/include/eunit.hrl").

decode_token(Token) ->
    TokenBin = base64url:decode(Token),
    HMAC = binary:part(TokenBin, byte_size(TokenBin), -256 div 8),
    RemainingToken = binary:part(TokenBin, 0, byte_size(TokenBin) - 256 div 8),
    <<128, Timestamp:64/integer, IV:128/bitstring, Ciphertext/binary>> = RemainingToken,
    {HMAC, RemainingToken, Timestamp, IV, Ciphertext}.

encode_message(Timestamp, IV, Ciphertext) ->
    <<128, Timestamp:64/integer, IV:128/bitstring, Ciphertext/binary>>.

encode_token(Message, HMAC) ->
    Token = base64url:encode(<<Message/bitstring, HMAC/bitstring>>),
    <<Token/bitstring, <<"==">>/bitstring>>.

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
    {HMAC, Message, Timestamp, IV, Ciphertext} = decode_token(Token),
    {SigningKey, EncryptionKey} = decode_key(Key),
    case valid_timestamp(Timestamp, CurrentTimestamp, TTL) of
        false ->
            throw(invalid_token);
        _ ->
            valid
    end,
    case valid_hmac(HMAC, Message, SigningKey) of
        false ->
            throw(invalid_token);
        _ ->
            valid
    end,
    PaddedPlaintext = crypto:block_decrypt(aes_cbc128, EncryptionKey, IV, Ciphertext),
    pkcs7:unpad(PaddedPlaintext).

encrypt(Plaintext, Key) ->
    IV = crypto:strong_rand_bytes(128 div 8),
    Timestamp = current_timestamp(),
    encrypt(Plaintext, Key, IV, Timestamp).

encrypt(Plaintext, Key, IV, Timestamp) ->
    {SigningKey, EncryptionKey} = decode_key(Key),
    PaddedPlaintext = pkcs7:pad(Plaintext),
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
valid_timestamp(Timestamp, CurrentTimestamp, TTL) when Timestamp + TTL > CurrentTimestamp ->
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


generate_key_test() ->
    decode_key(generate_key()).

decrypt_test() ->
    Key = <<"cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=">>,
    Token = <<"gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==">>,
    <<"hello">> = decrypt(Token, Key),
    ?assertThrow(invalid_token, decrypt(Token, Key, 60)),
    ?assertThrow(invalid_token, decrypt(<<"gAAAAAAdwJ6xAAECAwQFBgcICQoLDA0OD3HkMATM5lFqGaerZ-fWPAl1-szkFVzXTuGb4hR8AKtwcaX1YdykQUFBQUFBQUFBQQ==">>, <<"cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=">>)).

encrypt_test() ->
    Key = <<"cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=">>,
    IV = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>,
    Timestamp = 499162800,
    Plaintext = <<"hello">>,
    Token = <<"gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==">>,
    Token = encrypt(Plaintext, Key, IV, Timestamp).
