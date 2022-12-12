package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/elitah/fast-io"
	"github.com/elitah/utils/exepath"
	"github.com/elitah/utils/logs"
	"github.com/elitah/websocket/websocket"

	"github.com/xtaci/smux"
	"golang.org/x/net/proxy"
)

var (
	exeDir = exepath.GetExeDir()
)

func main() {
	var links uint64

	var local_addr, proxy_addr, remote_addr string

	var ca_path string

	flag.StringVar(&local_addr, "l", "", "Your local listen address")
	flag.StringVar(&proxy_addr, "p", "", "Your proxy address or url")
	flag.StringVar(&remote_addr, "r", "", "Your remote server address")

	flag.StringVar(&ca_path, "ca", exeDir+"/rootCA.bin", "Your CA Certificate file path")

	flag.Parse()

	logs.SetLogger(logs.AdapterConsole, `{"level":99,"color":true}`)
	logs.EnableFuncCallDepth(true)
	logs.SetLogFuncCallDepth(3)
	logs.Async()

	defer logs.Close()

	if "" == local_addr || "" == proxy_addr || "" == remote_addr {
		flag.Usage()
		return
	}

	if local_netinfo := strings.SplitN(local_addr, ":", 2); 2 <= len(local_netinfo) {
		if remote_netinfo := strings.SplitN(remote_addr, ":", 2); 2 <= len(remote_netinfo) {
			//
			var dialer proxy.Dialer
			//
			var ws_client *websocket.Client
			//
			switch local_netinfo[0] {
			case "tcp", "tcp4", "tcp6":
			case "udp", "udp4", "udp6":
			default:
				logs.Warn("unsupport protocol for local: %s", local_netinfo[0])
				return
			}
			//
			switch remote_netinfo[0] {
			case "tcp", "tcp4", "tcp6":
			case "udp", "udp4", "udp6":
			default:
				logs.Warn("unsupport protocol for remote: %s", remote_netinfo[0])
				return
			}
			//
			if strings.HasPrefix(proxy_addr, "ws://") || strings.HasPrefix(proxy_addr, "wss://") {
				ws := websocket.NewClient()

				defer ws.Close()

				ws_client = ws

				if strings.HasPrefix(proxy_addr, "wss://") && "" != ca_path {
					//
					if info, err := os.Stat(ca_path); nil == err {
						if 0 < info.Size() {
							if data, err := ioutil.ReadFile(ca_path); nil == err {
								pool := x509.NewCertPool()
								if pool.AppendCertsFromPEM(data) {
									ws.SetTLSConfig(&tls.Config{
										RootCAs:            pool,
										InsecureSkipVerify: false,
									})
								}
							}
						}
					}
				}

				_dialer := websocket.NewClientDialer(ws, proxy_addr)

				_dialer.SetHandler(func(conn net.Conn, network, addr string) (net.Conn, error) {
					if session, err := smux.Client(conn, nil); nil == err {
						if _conn, ok := conn.(*websocket.Conn); ok {
							// 最后连接数
							var last, current int = 1, 0
							// 启动闲置检测
							_conn.StartIdlaCheck(30*time.Second, func(before, now uint64) {
								//
								current = session.NumStreams()
								//
								logs.Info(last, current)
								//
								if before == now || (0 == last && 0 == current) {
									session.Close()
								} else {
									last = current
								}
							})
						}
						if _conn, _err := session.OpenStream(); nil == _err {
							var buffer [1024]byte
							//
							logs.Info(network, addr)
							//
							fmt.Fprintf(_conn, "%s:%s", network, addr)
							//
							_conn.SetReadDeadline(time.Now().Add(5 * time.Second))
							//
							if n, __err := _conn.Read(buffer[:]); nil == __err {
								if 0 < n {
									if 2 == n && "ok" == string(buffer[:n]) {
										//
										_conn.SetReadDeadline(time.Time{})
										//
										return _conn, nil
									}
									err = fmt.Errorf("connect failed")
								} else {
									err = fmt.Errorf("short read")
								}
							} else {
								err = __err
							}
							//
							_conn.Close()
						} else {
							err = _err
						}
						//
						session.Close()
						//
						return nil, err
					} else {
						return nil, err
					}
				})

				dialer = _dialer
			} else {
				if _dialer, err := proxy.SOCKS5("tcp", proxy_addr, nil, nil); nil == err {
					dialer = _dialer
				} else {
					logs.Error(err)
				}
			}
			//
			if nil != dialer {
				//
				var closer io.Closer
				//
				switch local_netinfo[0] {
				case "tcp", "tcp4", "tcp6":
					if listener, err := net.Listen(local_netinfo[0], local_netinfo[1]); nil == err {
						go func() {
							for {
								if local_conn, err := listener.Accept(); nil == err {
									if remote_conn, err := dialer.Dial(remote_netinfo[0], remote_netinfo[1]); nil == err {
										go func() {
											//
											atomic.AddUint64(&links, 1)
											//
											fast_io.FastCopy(local_conn, remote_conn)
											//
											atomic.AddUint64(&links, ^uint64(0))
										}()
									} else {
										logs.Error(err)
										//
										local_conn.Close()
									}
								} else {
									logs.Error(err)

									break
								}
							}
						}()
						//
						closer = listener
					} else {
						logs.Error(err)
					}
				case "udp", "udp4", "udp6":
					if addr, err := net.ResolveUDPAddr(local_netinfo[0], local_netinfo[1]); nil == err {
						if local_conn, err := net.ListenUDP(local_netinfo[0], addr); nil == err {
							go func() {
								//
								var remote net.Conn
								//
								var buffer [1024 * 32]byte
								//
								var err error
								var rn, wn int
								//
								for {
									if rn, err = local_conn.Read(buffer[:]); nil == err {
										if 0 < rn {
											//
											logs.Info("Recv package: %d", rn)
											//
											if nil != remote {
												if wn, err = remote.Write(buffer[:rn]); nil == err {
													logs.Info("Send done: %d / %d", wn, rn)
													continue
												} else {
													logs.Error(err)
												}
												//
												atomic.AddUint64(&links, ^uint64(0))
												//
												remote.Close()
											}
											if remote, err = dialer.Dial(remote_netinfo[0], remote_netinfo[1]); nil == err {
												//
												atomic.AddUint64(&links, 1)
												//
												remote.Write(buffer[:rn])
											} else {
												logs.Error(err)
											}
										} else {
											logs.Error("empty recv")
										}
									} else {
										logs.Error(err)

										return
									}
								}
							}()
							//
							closer = local_conn
						} else {
							logs.Error(err)
						}
					} else {
						logs.Error(err)
					}
				}
				//
				if nil != closer {
					defer closer.Close()

					ticker := time.NewTicker(3 * time.Second)

					defer ticker.Stop()

					sig := make(chan os.Signal, 1)

					signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

					for {
						select {
						case s, ok := <-sig:
							//
							if ok {
								logs.Info("exit by %v", s)
							}
							//
							close(sig)
							//
							return
						case <-ticker.C:
							//
							logs.Info("=== links: %d ============================", atomic.LoadUint64(&links))
							//
							if nil != ws_client {
								logs.Info("=== report(%d) ============================", ws_client.Len())
								//
								for _, item := range ws_client.Lists() {
									logs.Info(item)
								}
							}
							logs.Info("=======================================\r\n\r\n")
						}
					}
				}
			}
		} else {
			logs.Error("invalid remote address: %s", remote_addr)
		}
	} else {
		logs.Error("invalid local address: %s", local_addr)
	}
}
