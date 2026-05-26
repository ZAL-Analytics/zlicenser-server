package zlicenser_server

// #cgo LDFLAGS: -L${SRCDIR}/../../target/debug -lzlicenser_server_go -Wl,-rpath,${SRCDIR}/../../target/debug
// #include "zlicenser_server.h"
import "C"

func HelloWorld() string {
	return C.GoString(C.zlicenser_server_hello_world())
}
