-module(oauth_unit).

-compile(export_all).


tests() ->
  tests("data").

tests(Path) ->
  signature_base_string_tests(Path),
  plaintext_signature_tests(Path),
  plaintext_verify_tests(Path),
  hmac_sha1_signature_tests(Path),
  hmac_sha1_verify_tests(Path),
  rsa_sha1_signature_test(Path),
  rsa_sha1_verify_test(Path).

signature_base_string_tests(Dirname) ->
  foreach(Dirname, "base_string_test_*", fun(Path) ->
    [Method, URL, Params, BaseString] = path_get_values([method, url, params, base_string], Path),
    test(Path, oauth, signature_base_string, [Method, URL, Params], BaseString)
  end).

plaintext_signature_tests(Dirname) ->
  foreach(Dirname, "plaintext_test_*", fun(Path) ->
    [CS, TS, Signature] = path_get_values([cs, ts, signature], Path),
    test(Path, oauth_plaintext, signature, [CS, TS], Signature)
  end).

plaintext_verify_tests(Dirname) ->
  foreach(Dirname, "plaintext_test_*", fun(Path) ->
    [CS, TS, Signature] = path_get_values([cs, ts, signature], Path),
    test(Path, oauth_plaintext, verify, [Signature, CS, TS], true)
  end).

hmac_sha1_signature_tests(Dirname) ->
  foreach(Dirname, "hmac_sha1_test_*", fun(Path) ->
    [BaseString, CS, TS, Signature] = path_get_values([base_string, cs, ts, signature], Path),
    test(Path, oauth_hmac_sha1, signature, [BaseString, CS, TS], Signature)
  end).

hmac_sha1_verify_tests(Dirname) ->
  foreach(Dirname, "hmac_sha1_test_*", fun(Path) ->
    [BaseString, CS, TS, Signature] = path_get_values([base_string, cs, ts, signature], Path),
    test(Path, oauth_hmac_sha1, verify, [Signature, BaseString, CS, TS], true)
  end).

rsa_sha1_signature_test(Dirname) ->
  Path = filename:join(Dirname, "rsa_sha1_test"),
  Key = filename:join(Dirname, "rsa_sha1_private_key.pem"),
  [BaseString, Signature] = path_get_values([base_string, signature], Path),
  test("rsa_sha1_test", oauth_rsa_sha1, signature, [BaseString, Key], Signature).

rsa_sha1_verify_test(Dirname) ->
  Path = filename:join(Dirname, "rsa_sha1_test"),
  Cert = filename:join(Dirname, "rsa_sha1_certificate.pem"),
  [BaseString, Signature] = path_get_values([base_string, signature], Path),
  test("rsa_sha1_test", oauth_rsa_sha1, verify, [Signature, BaseString, Cert], true).

test(Path, M, F, A, Expected) ->
  case apply(M, F, A) of
    Expected ->
      io:format("ok - ~p:~p (~s)~n", [M, F, Path]);
    Actual ->
      io:format("not ok - ~p:~p (~s)~n", [M, F, Path]),
      io:format(comment(iolist_to_binary(io_lib:format("~p~n", [Actual]))))
  end.

path_get_values(Keys, Path) ->
  {ok, Proplist} = file:consult(Path),
  proplist_get_values(Keys, Proplist).

proplist_get_values(Keys, Proplist) ->
  [proplists:get_value(K, Proplist) || K <- Keys].

foreach(Dirname, Basename, Fun) ->
  lists:foreach(Fun, filelib:wildcard(filename:join(Dirname, Basename))).

comment(String) ->
  re:replace(String, "^", "# ", [global, multiline]).
