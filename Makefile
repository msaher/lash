# .PHONY: run
# run: src/vendor-luv/build/libluv.a
# 	odin run src

src/luv/build/libluv.a:
	BUILD_MODULE=OFF BUILD_STATIC_LIBS=ON $(MAKE) -C src/vendor-luv
