BUILD=ocaml setup.ml

all:V: setup.data
	$BUILD -build
	$BUILD -doc

setup.data:
	$BUILD -configure

clean:V:
	$BUILD -distclean

install:V:
	$BUILD -uninstall
	rm -rf /usr/local/lib/ocaml/site-lib/cryptokit
	$BUILD -install
