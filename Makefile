test:
	./rebar3 compile
	./rebar3 eunit
	./rebar3 dialyzer

clean:
	rm -Rf ./_build

.PHONY: test
