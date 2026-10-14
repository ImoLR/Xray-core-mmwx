package wireguard

import (
	"encoding/hex"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// 本文件是 mmwx fork 在上游 #6360(WireGuard 入站动态 peer 管理)之上加的校验。
// 限速、并发连接数与 per-user 流量统计都靠 GetUserByAddr 按隧道内源地址落到某个 peer 上归属,
// 所以 peer 的身份(公钥、email、allowed_ips)必须无歧义;上游只做了「peer 公钥 == 服务端公钥」一项。

// ValidateDeviceUsers 按 NewServer 加载时的同一套规则校验服务端(入站)设备的用户,不创建任何设备。
//
// infra/conf 在 WireGuardConfig.Build(!IsClient)里调用它,让重复公钥、allowed_ips 非规范或
// 彼此重叠这类坏配置在 LoadJSONConfig 阶段就被拒绝。否则要等到 NewServer 才炸:写盘前的配置测试
// (只跑 LoadJSONConfig)拦不住,整入站替换时旧入站已经删掉、新的又加不回来,下次重启整机 xray 起不来。
//
// 与 NewServer 共用 collectDeviceUsers,两处不会漂移:比 NewServer 更严会让原本能跑的配置升级后起不来,
// 更松则拦不住上面的问题。
func ValidateDeviceUsers(users []*protocol.User) error {
	_, err := collectDeviceUsers(users)
	return err
}

// collectDeviceUsers 把配置里的用户收敛成设备实际装载的用户集合,并做全部校验:
//   - 带 email 的用户:公钥按解码后的 32 字节比较、互不重复;email 互不重复
//   - 匿名(email 为空,即旧配置里的 peer):公钥已出现过(带 email 的用户或更早的匿名 peer)的静默忽略,
//     不报错,也不参与后面的重叠检查 —— 与 fork 合并上游之前的行为一致,既有配置升级后照常能起
//   - 剩下的全体交给 validateAllowedIPs
func collectDeviceUsers(users []*protocol.User) ([]*protocol.MemoryUser, error) {
	parsed := make([]*protocol.MemoryUser, 0, len(users))
	for _, u := range users {
		mu, err := u.ToMemoryUser()
		if err != nil {
			return nil, errors.New("failed to parse wireguard user ", u.Email).Base(err)
		}
		if _, ok := mu.Account.(*MemoryAccount); !ok {
			return nil, errors.New("unexpected account type for wireguard user ", u.Email)
		}
		parsed = append(parsed, mu)
	}

	all := make([]*protocol.MemoryUser, 0, len(parsed))
	seenPub := make(map[[32]byte]bool, len(parsed))
	seenEmail := make(map[string]bool, len(parsed))
	for _, mu := range parsed {
		if mu.Email == "" {
			continue
		}
		pub := mu.Account.(*MemoryAccount).Pub
		if seenPub[pub] {
			return nil, errors.New("duplicated wireguard peer public key for user ", mu.Email)
		}
		// 同一 email 两个 peer:RemoveUser(email) 只删得掉其中一个,两份流量记到同一个人头上。
		if seenEmail[mu.Email] {
			return nil, errors.New("duplicated wireguard peer email ", mu.Email)
		}
		seenPub[pub] = true
		seenEmail[mu.Email] = true
		all = append(all, mu)
	}
	for _, mu := range parsed {
		if mu.Email != "" {
			continue
		}
		pub := mu.Account.(*MemoryAccount).Pub
		if seenPub[pub] {
			continue
		}
		seenPub[pub] = true
		all = append(all, mu)
	}

	if err := validateAllowedIPs(all); err != nil {
		return nil, err
	}
	return all, nil
}

// checkNewUser 是 AddUser 在下发给设备之前的检查:公钥、email 不能与现有用户重复,地址不能与现有用户重叠。
// 同 email 再加一个 peer(典型是换密钥时先加后删)会让 RemoveUser(email) 之后只删得掉其中一个,
// 另一个继续以同一身份在线计费,所以换密钥必须先 RemoveUser 再 AddUser。
func (s *Server) checkNewUser(user *protocol.MemoryUser) error {
	peer := user.Account.(*MemoryAccount)
	if _, dup := s.users.Load(peer.Pub); dup {
		return errors.New("wireguard: peer public key already exists")
	}
	var all []*protocol.MemoryUser
	dupEmail := false
	s.users.Range(func(key, value any) bool {
		u := value.(*protocol.MemoryUser)
		if user.Email != "" && u.Email == user.Email {
			dupEmail = true
		}
		all = append(all, u)
		return true
	})
	if dupEmail {
		return errors.New("wireguard: peer email already exists: ", user.Email)
	}
	return validateAllowedIPs(append(all, user))
}

// validateAllowedIPs 校验 allowed_ips 足以作为「身份」使用。
//
// GetUserByAddr 是按隧道内源地址落到某个 peer 的 allowed_ips 上来归属流量的,所以地址集合一旦重叠,
// 归属就取决于 sync.Map 的遍历顺序 —— 表现为流量、配额和限速随机算到另一个用户头上,且没有任何报错。
// 宁可在启动/加用户时炸掉。
//
// 没有任何 peer 带 email 时直接放行:那是纯粹的旧配置,本来就没有用户身份,
// allowed_ips 写 0.0.0.0/0 是合法且常见的,不能把它判成非法。
func validateAllowedIPs(users []*protocol.MemoryUser) error {
	type entry struct {
		name string
		acc  *MemoryAccount
	}

	var all []entry
	hasEmail := false
	for _, u := range users {
		acc, ok := u.Account.(*MemoryAccount)
		if !ok {
			continue
		}
		name := u.Email
		if name == "" {
			name = "peer " + hex.EncodeToString(acc.Pub[:4])
		} else {
			hasEmail = true
		}
		all = append(all, entry{name, acc})
	}
	if !hasEmail {
		return nil
	}

	for _, e := range all {
		if len(e.acc.AllowedIPs) == 0 {
			return errors.New("wireguard ", e.name, ": empty allowed_ips, user would be unidentifiable")
		}
		for _, pfx := range e.acc.AllowedIPs {
			if pfx.Masked() != pfx {
				return errors.New("wireguard ", e.name, ": allowed_ip ", pfx.String(), " is not in canonical form")
			}
		}
	}

	for i := range all {
		for j := i + 1; j < len(all); j++ {
			for _, a := range all[i].acc.AllowedIPs {
				for _, b := range all[j].acc.AllowedIPs {
					if a.Contains(b.Addr()) || b.Contains(a.Addr()) {
						return errors.New("wireguard: allowed_ip ", a.String(), " of ", all[i].name,
							" overlaps ", b.String(), " of ", all[j].name, "; traffic attribution would be ambiguous")
					}
				}
			}
		}
	}
	return nil
}
