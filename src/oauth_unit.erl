-module(oauth_unit).

-compile(export_all).


tests() ->
  tests("data").

tests(Path) ->
  signature_base_string_tests(Path),
  plaintext_signature_tests(Path),
  hmac_sha1_signature_tests(Path),
  rsa_sha1_signature_test(Path).

signature_base_string_tests(Path) ->
  TestPaths = filename:join(Path, "base_string_test_*"),
  test_each(TestPaths, oauth, signature_base_string, [method, url, params], base_string).

plaintext_signature_tests(Path) ->
  TestPaths = filename:join(Path, "plaintext_signature_test_*"),
  test_each(TestPaths, oauth_plaintext, signature, [cs, ts], signature).

hmac_sha1_signature_tests(Path) ->
  TestPaths = filename:join(Path, "hmac_sha1_signature_test_*"),
  test_each(TestPaths, oauth_hmac_sha1, signature, [base_string, cs, ts], signature).

rsa_sha1_signature_test(Path) ->
  TestPath = filename:join(Path, "rsa_sha1_signature_test"),
  {ok, Test} = file:consult(TestPath),
  Args = [proplists:get_value(base_string, Test), filename:join(Path, "rsa_sha1_private_key.pem")],
  test(TestPath, {oauth_rsa_sha1, signature, Args}, proplists:get_value(signature, Test)).

test_each(Paths, M, F, A, R) ->
  lists:foreach(fun(Path) -> test(Path, M, F, A, R) end, filelib:wildcard(Paths)).

test(Path, M, F, A, R) ->
  {ok, Test} = file:consult(Path),
  test(Path, {M, F, [proplists:get_value(Key, Test) || Key <- A]}, proplists:get_value(R, Test)).

test(Tag, {M, F, A}, R) ->
  case apply(M, F, A) of
    R ->
      io:format("ok - ~s~n", [Tag]);
    Else ->
      io:format("not ok - ~s~n", [Tag]),
      io:format(comment(iolist_to_binary(io_lib:format("~p~n", [Else]))))
  end.

comment(String) ->
  re:replace(String, "^", "# ", [global, multiline]).
