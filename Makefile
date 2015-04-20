test:
	./rebar3 compile
	./rebar3 eunit
	./rebar3 dialyzer

.PHONY: test
