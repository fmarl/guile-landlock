SHIM_SRC=shim.c
SHIM_O=shim.so

all:
	gcc -O2 -fPIC -shared -fvisibility=default -o ${SHIM_O} src/${SHIM_SRC} -Wl,--export-dynamic

clean:
	rm -rf ${SHIM_O}
