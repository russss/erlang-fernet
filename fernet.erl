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
    io:format("Signing key: ~w, Encryption key: ~w~n", [SigningKey, EncryptionKey]),
    {SigningKey, EncryptionKey}.

generate_key() ->
    SigningKey = crypto:strong_rand_bytes(128 div 8),
    EncryptionKey = crypto:strong_rand_bytes(128 div 8),
    KeyBin = <<SigningKey:128/bitstring, EncryptionKey:128/bitstring>>,
    base64url:encode(KeyBin).

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
    io:format("Padded plaintext: ~w~n", [PaddedPlaintext]),
    pkcs7:unpad(PaddedPlaintext).

encrypt(Plaintext, Key) ->
    IV = crypto:strong_rand_bytes(128 div 8),
    Timestamp = current_timestamp(),
    encrypt(Plaintext, Key, IV, Timestamp).

encrypt(Plaintext, Key, IV, Timestamp) ->
    {SigningKey, EncryptionKey} = decode_key(Key),
    PaddedPlaintext = pkcs7:pad(Plaintext),
    io:format("Padded plaintext: ~w~n", [PaddedPlaintext]),
    Ciphertext = crypto:block_encrypt(aes_cbc128, EncryptionKey, IV, PaddedPlaintext),
    Message = encode_message(Timestamp, IV, Ciphertext),
    HMAC = hmac_sha256(SigningKey, Message),
    encode_token(Message, HMAC).

hmac_sha256(Key, Data) ->
    crypto:hmac(sha256, Key, Data).

valid_hmac(HMAC, Data, Key) ->
    CalculatedHMAC = hmac_sha256(Key, Data),
    %% TODO: this is not a constant-time comparison!
    case CalculatedHMAC of
        HMAC ->
            true;
        _ ->
            false
    end.

valid_timestamp(_Timestamp, _CurrentTimestamp, TTL) when TTL == none ->
    true;
valid_timestamp(Timestamp, CurrentTimestamp, TTL) when Timestamp + TTL > CurrentTimestamp ->
    true;
valid_timestamp(_Timestamp, _CurrentTimestamp, _TTL) ->
    false.

current_timestamp() ->
    {Mega, Sec, Micro} = os:timestamp(),
    Mega * 1000000 * 1000000 + Sec * 1000000 + Micro.


decrypt_test() ->
    Key = <<"cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=">>,
    Token = <<"gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==">>,
    <<"hello">> = decrypt(Token, Key),
    ?assertThrow(invalid_token, decrypt(Token, Key, 60)).

encrypt_test() ->
    Key = <<"cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=">>,
    IV = <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15>>,
    Timestamp = 499162800,
    Plaintext = <<"hello">>,
    Token = <<"gAAAAAAdwJ6wAAECAwQFBgcICQoLDA0ODy021cpGVWKZ_eEwCGM4BLLF_5CV9dOPmrhuVUPgJobwOz7JcbmrR64jVmpU4IwqDA==">>,
    Token = encrypt(Plaintext, Key, IV, Timestamp).
