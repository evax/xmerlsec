all: compile

compile:
	rebar compile

test: compile
	rebar eunit

.PHONY: test
