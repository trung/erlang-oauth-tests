Test code for erlang-oauth (http://github.com/tim/erlang-oauth).

To run the unit tests:

  $ make
  ...
  $ erl -pa ebin -pa ../erlang-oauth/ebin -s crypto -noshell -s oauth_unit tests -s init stop
  ...
