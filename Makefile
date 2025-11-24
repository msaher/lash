.PHONY: build
build: src/vendor-luv/build/libluv.a
	odin build src -out:lash -error-pos-style:unix

src/luv/build/libluv.a:
	BUILD_MODULE=OFF BUILD_STATIC_LIBS=ON $(MAKE) -C src/vendor-luv


