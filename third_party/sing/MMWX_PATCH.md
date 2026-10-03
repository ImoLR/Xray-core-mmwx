# sing v0.5.1 + mmwx 补丁

原样拷自 `github.com/sagernet/sing@v0.5.1`(GPL-3.0,见同目录 LICENSE),只改了一处:

- `common/udpnat/service.go` `NewContextPacket`:向会话队列发包时同时认 `c.ctx.Done()`。
  原版是无条件阻塞发送,会话的消费者一退出(限速踢连接、下行 60 秒超时、闲置清理),
  调用方 —— SS2022 入站的 UDP 读循环 —— 就连同队列里的包永久卡住,
  表现为开限速后 agent 内存只涨不降、重启才恢复。上游 v0.8.14 仍是同样写法。

升级 sing 版本时要把这处补丁一起带过去,或者确认上游已经修掉。
