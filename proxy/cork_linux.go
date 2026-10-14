package proxy

import (
	"io"
	"syscall"

	"golang.org/x/sys/unix"
)

// setCork 塞住 / 放开 w 的发送(TCP_CORK):塞住期间写进去的小块不单独成包,放开时一并发出。
// w 不是 TCP 连接时什么也不做。
func setCork(w io.Writer, on bool) {
	sc, ok := w.(syscall.Conn)
	if !ok {
		return
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return
	}
	v := 0
	if on {
		v = 1
	}
	_ = rc.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_CORK, v)
	})
}

// waitSendRoom 等 w 的内核发送缓冲里还没发出去的字节(TCP_INFO 的 tcpi_notsent_bytes)降到 limit 以下。
// 同时把 TCP_NOTSENT_LOWAT 设成 limit:等待由 epoll 在未发送字节降到它以下时唤醒,不忙等。
//
// 只靠 TCP_NOTSENT_LOWAT 压不住积压:它只管 socket 什么时候被报告可写,写本身只受整个发送缓冲限制,
// Go 会一直写到缓冲满(慢链路上自动调到近 1 MB)。积压的数据都排在入站之后要写的帧(中止后的 END)前面,
// 2 Mbps 时要 3 秒多才轮得到,客户端等不及就把通道关了。
func waitSendRoom(w io.Writer, limit int) {
	sc, ok := w.(syscall.Conn)
	if !ok {
		return
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, limit)
	})
	_ = rc.Write(func(fd uintptr) bool {
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if err != nil || int(info.Notsent_bytes) < limit {
			return true
		}
		// 要等了。内核只在 socket 先被报告过「写不进」(SOCK_NOSPACE)之后,空间腾出来才发可写通知;
		// 这里没写也没 poll 过,不先 poll 一次的话通知永远不来(实测一停好几秒,直到有数据进来顺带叫醒)。
		// poll 时未发字节已经降到可写线以下就直接走。
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		if n, err := unix.Poll(fds, 0); err != nil || (n > 0 && fds[0].Revents&unix.POLLOUT != 0) {
			return true
		}
		return false
	})
}
