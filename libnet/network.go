package libnet

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"

	"SimpleAsyncBFT/message"
)

type methodType struct {
	method  reflect.Method // Func to execute.
	ArgType reflect.Type   // Func parameter type.
}

type Network struct {
	logger  *log.Logger         // Global log.
	mu      sync.Mutex          // Lock to prevent race condition.
	port    string              // Network port.
	conns   map[string]net.Conn // Cache all remote connection. e.g. {'RemoteAddr': net.conn}.
	service map[string]*Service // Cache all service. e.g. consensus service or connect service.
}

func MakeNetwork(port string, logger *log.Logger) *Network {
	rn := &Network{}
	rn.logger = logger
	rn.port = port
	rn.conns = make(map[string]net.Conn)
	rn.service = make(map[string]*Service)
	return rn
}

func (rn *Network) Start() {
	listen, err := net.Listen("tcp", rn.port)

	if err != nil {
		rn.logger.Fatalf("Socket listen port %s failed, %s", rn.port, err)
		os.Exit(1)
	}

	defer listen.Close()

	rn.logger.Printf("Network port %s\n", rn.port)

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Fatalln(err)
			continue
		}
		rn.conns[conn.RemoteAddr().String()] = conn
		go rn.handleConn(conn)
	}
}

// func (rn *Network) PrintHello(m message.Proof) {
// 	rn.logger.Println(m)
// }

func (rn *Network) GetConn(remoteAddr string) net.Conn {
	if conn, ok := rn.conns[remoteAddr]; ok {
		return conn
	}
	return nil
}

func (rn *Network) handleConn(conn net.Conn) {
	defer func() {
		rn.logger.Printf("Remote machine [%s] close connection.\n", conn.RemoteAddr().String())
		delete(rn.conns, conn.RemoteAddr().String())
		conn.Close()
	}()

	dec := json.NewDecoder(conn)

	for {
		var req message.ReqMsg
		if err := dec.Decode(&req); err == io.EOF {
			// remote machine close connection.
			break
		} else if err != nil {
			// network error.
			rn.logger.Println(err)
			break
		}
		fmt.Println(req)
		go rn.netDispatch(req)
	}
}

func (rn *Network) netDispatch(req message.ReqMsg) {
	dot := strings.LastIndex(req.SvcMeth, ".")
	serviceName := req.SvcMeth[:dot]
	methodName := req.SvcMeth[dot+1:]

	servce, ok := rn.service[serviceName]

	if ok {
		servce.dispatch(methodName, req)
	} else {
		rn.logger.Printf("Service : %s not found.\n", serviceName)
	}
}

type Service struct {
	name    string                 // Service name.
	rcvr    reflect.Value          // Service values (pointer).
	typ     reflect.Type           // Service type.
	methods map[string]*methodType // Service Methods.
}

// Register service.
func (rn *Network) AddService(svc *Service) {
	rn.mu.Lock()
	defer rn.mu.Unlock()
	rn.service[svc.name] = svc
}

func MakeService(rcvr interface{}) *Service {
	svc := &Service{}
	svc.typ = reflect.TypeOf(rcvr)
	svc.rcvr = reflect.ValueOf(rcvr)
	svc.name = reflect.Indirect(svc.rcvr).Type().Name()
	svc.methods = map[string]*methodType{}

	for m := 0; m < svc.typ.NumMethod(); m++ {
		method := svc.typ.Method(m)
		mtype := method.Type
		mname := method.Name

		if method.PkgPath != "" || mtype.NumIn() != 2 {
			continue
		} else {
			svc.methods[mname] = &methodType{method: method, ArgType: mtype.In(1)}
			fmt.Printf("[%v] register {method: %v, argsType: %v}.\n", svc.name, mname, mtype.In(1))
		}
	}

	return svc
}

func (svc *Service) dispatch(methname string, req message.ReqMsg) {
	if method, ok := svc.methods[methname]; ok {
		// prepare space into which to read the element.
		args := reflect.New(method.ArgType)

		// decode args.
		ab := bytes.NewBuffer(req.Args)
		ad := gob.NewDecoder(ab)
		ad.Decode(args.Interface())

		fmt.Println(args.Type())
		fmt.Println(args)

		// call the method.
		function := method.method.Func
		function.Call([]reflect.Value{svc.rcvr, args.Elem()})
	}
}
