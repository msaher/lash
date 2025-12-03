.PHONY: build
build: src/vendor-luv/build/libluv.a src/libssh-0.11.3/build/src/libssh.a
	odin build src -out:lash -error-pos-style:unix

src/luv/build/libluv.a:
	BUILD_MODULE=OFF BUILD_STATIC_LIBS=ON $(MAKE) -C src/vendor-luv

src/libssh-0.11.3/build/src/libssh.a:
	mkdir -p src/libssh-0.11.3/build && \
	cd src/libssh-0.11.3/build && \
	cmake -DUNIT_TESTING=ON -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Debug .. && \
	make
