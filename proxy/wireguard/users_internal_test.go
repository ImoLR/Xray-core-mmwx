package wireguard

import (
	"context"
	"encoding/hex"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"golang.org/x/crypto/curve25519"
)

func pubHex(b byte) string {
	return strings.Repeat(string("0123456789abcdef"[b&0xf]), 64)
}

// newTestServer 只装用户表、不建设备,走的是 NewServer 里同一个 collectDeviceUsers。
// peers 是旧形态的匿名 peer,合并上游后在 infra/conf 里就被建成 email 为空的用户,这里照此拼接。
func newTestServer(t *testing.T, conf *DeviceConfig, peers ...*PeerConfig) (*Server, error) {
	t.Helper()
	s := &Server{conf: conf, users: new(sync.Map)}
	all, err := collectDeviceUsers(append(conf.Users, anonymous(peers)...))
	if err != nil {
		return s, err
	}
	for _, u := range all {
		s.users.Store(u.Account.(*MemoryAccount).Pub, u)
	}
	return s, nil
}

func anonymous(peers []*PeerConfig) []*protocol.User {
	var out []*protocol.User
	for _, p := range peers {
		out = append(out, named("", p))
	}
	return out
}

func named(email string, p *PeerConfig) *protocol.User {
	return &protocol.User{Email: email, Account: serial.ToTypedMessage(p)}
}

func mustUsers(t *testing.T, users ...*protocol.User) []*protocol.User {
	t.Helper()
	return users
}

func peer(pub string, ips ...string) *PeerConfig {
	return &PeerConfig{PublicKey: pub, AllowedIps: ips}
}

// 两个用户各自一个 /32:归属必须精确,且互不串味。这是整个 per-user 计费的地基。
func TestLoadUsersDistinctHostPrefixes(t *testing.T) {
	conf := &DeviceConfig{SecretKey: pubHex(1)}
	conf.Users = mustUsers(t,
		named("alice", peer(pubHex(2), "10.0.0.2/32", "fd00::2/128")),
		named("bob", peer(pubHex(3), "10.0.0.3/32", "fd00::3/128")),
	)

	s, err := newTestServer(t, conf)
	if err != nil {
		t.Fatalf("loadUsers: %v", err)
	}
	if got := s.GetUsersCount(context.Background()); got != 2 {
		t.Fatalf("GetUsersCount = %d, want 2", got)
	}

	for _, tc := range []struct{ addr, want string }{
		{"10.0.0.2", "alice"},
		{"10.0.0.3", "bob"},
		{"fd00::2", "alice"},
		{"fd00::3", "bob"},
	} {
		u := s.GetUserByAddr(context.Background(), netip.MustParseAddr(tc.addr))
		if u == nil || u.Email != tc.want {
			t.Fatalf("GetUserByAddr(%s) = %v, want %s", tc.addr, u, tc.want)
		}
	}
	// 不属于任何 peer 的地址不应该被硬塞给某个用户
	if u := s.GetUserByAddr(context.Background(), netip.MustParseAddr("10.0.0.9")); u != nil {
		t.Fatalf("GetUserByAddr(10.0.0.9) = %v, want nil", u.Email)
	}
	if u := s.GetUser(context.Background(), "bob"); u == nil {
		t.Fatal("GetUser(bob) = nil")
	}
}

// 重叠的 allowed_ips 会让归属取决于 map 遍历顺序 —— 必须在加载期就拒绝。
func TestLoadUsersRejectsOverlap(t *testing.T) {
	for name, ips := range map[string][2][]string{
		"subnet-contains-host": {{"10.0.0.0/24"}, {"10.0.0.3/32"}},
		"identical":            {{"10.0.0.2/32"}, {"10.0.0.2/32"}},
		"default-catch-all":    {{"0.0.0.0/0"}, {"10.0.0.3/32"}},
		"v6-overlap":           {{"fd00::/64"}, {"fd00::3/128"}},
	} {
		t.Run(name, func(t *testing.T) {
			conf := &DeviceConfig{SecretKey: pubHex(1)}
			conf.Users = mustUsers(t,
				named("alice", peer(pubHex(2), ips[0]...)),
				named("bob", peer(pubHex(3), ips[1]...)),
			)
			if _, err := newTestServer(t, conf); err == nil {
				t.Fatal("expected overlap to be rejected, got nil error")
			}
		})
	}
}

// 非规范写法(10.0.0.5/24)几乎总是笔误,静默按 10.0.0.0/24 生效会吞掉整段。
func TestLoadUsersRejectsNonCanonicalPrefix(t *testing.T) {
	conf := &DeviceConfig{SecretKey: pubHex(1)}
	conf.Users = mustUsers(t, named("alice", peer(pubHex(2), "10.0.0.5/24")))
	if _, err := newTestServer(t, conf); err == nil {
		t.Fatal("expected non-canonical prefix to be rejected")
	}
}

// 纯旧配置(只有匿名 peers)必须原样工作:它本来就没有用户身份,
// 0.0.0.0/0 是合法且常见的,不能被本次改动判成非法。
func TestLoadUsersLegacyAnonymousPeersUnaffected(t *testing.T) {
	conf := &DeviceConfig{SecretKey: pubHex(1)}
	s, err := newTestServer(t, conf, peer(pubHex(2), "0.0.0.0/0", "::/0"))
	if err != nil {
		t.Fatalf("legacy config rejected: %v", err)
	}
	if got := s.GetUsersCount(context.Background()); got != 1 {
		t.Fatalf("GetUsersCount = %d, want 1", got)
	}
	if u := s.GetUserByAddr(context.Background(), netip.MustParseAddr("10.0.0.9")); u == nil || u.Email != "" {
		t.Fatalf("legacy peer should resolve anonymously, got %v", u)
	}
}

// 一旦有带 email 的用户,匿名的 0.0.0.0/0 peer 就会把它的流量抢走,必须拒绝混用。
func TestLoadUsersRejectsMixedAnonymousCatchAll(t *testing.T) {
	conf := &DeviceConfig{SecretKey: pubHex(1)}
	conf.Users = mustUsers(t, named("alice", peer(pubHex(2), "10.0.0.2/32")))
	if _, err := newTestServer(t, conf, peer(pubHex(4), "0.0.0.0/0", "::/0")); err == nil {
		t.Fatal("expected anonymous catch-all peer to be rejected alongside an emailed user")
	}
}

// 同一公钥重复出现会让 IPC 与内存表漂移,归属静默出错。
func TestLoadUsersRejectsDuplicatePublicKey(t *testing.T) {
	conf := &DeviceConfig{SecretKey: pubHex(1)}
	conf.Users = mustUsers(t,
		named("alice", peer(pubHex(2), "10.0.0.2/32")),
		named("bob", peer(pubHex(2), "10.0.0.3/32")),
	)
	if _, err := newTestServer(t, conf); err == nil {
		t.Fatal("expected duplicate public key to be rejected")
	}
}

// 每个用户都必须进用户表(上游 Start 按它生成初始 IPC),否则用户握手直接失败。
func TestLoadUsersCoversAllUsers(t *testing.T) {
	conf := &DeviceConfig{SecretKey: pubHex(1)}
	conf.Users = mustUsers(t,
		named("alice", peer(pubHex(2), "10.0.0.2/32")),
		named("bob", peer(pubHex(3), "10.0.0.3/32")),
	)
	s, err := newTestServer(t, conf)
	if err != nil {
		t.Fatalf("loadUsers: %v", err)
	}
	for _, email := range []string{"alice", "bob"} {
		if s.GetUser(context.Background(), email) == nil {
			t.Fatalf("user %s missing from the user table", email)
		}
	}
}

// ValidateDeviceUsers 是 infra/conf Build 提前拦坏配置用的,它与 NewServer 的判定必须
// 完全一致:更严会让原本能跑的配置升级后起不来,更松则拦不住会让 NewServer 炸掉的配置。
func TestValidateDeviceUsersAgreesWithLoadUsers(t *testing.T) {
	upper := strings.ToUpper("ab" + strings.Repeat("0", 62))
	lower := "ab" + strings.Repeat("0", 62)
	var serverPub, serverPriv [32]byte
	copy(serverPriv[:], common.Must2(hex.DecodeString(pubHex(1))))
	curve25519.ScalarBaseMult(&serverPub, &serverPriv)
	cases := []struct {
		name    string
		users   []*protocol.User
		peers   []*PeerConfig
		wantErr bool
	}{
		{
			name: "distinct-dual-stack-hosts",
			users: []*protocol.User{
				named("alice", peer(pubHex(2), "10.0.0.2/32", "fd00::2/128")),
				named("bob", peer(pubHex(3), "10.0.0.3/32", "fd00::3/128")),
			},
		},
		{
			// 主控的探测 peer / 中转 peer 形态:email + /32 + /128,IPAM 分配,互不重叠
			name: "probe-and-transit-shape",
			users: []*protocol.User{
				named("alice__wg-in", peer(pubHex(2), "10.66.0.2/32", "fd66::2/128")),
				named("__wgprobe__", peer(pubHex(3), "10.66.3.254/32", "fd66::3fe/128")),
				named("__wgtransit__1", peer(pubHex(4), "10.66.0.5/32")),
			},
		},
		{
			name:  "legacy-anonymous-catch-all",
			peers: []*PeerConfig{peer(pubHex(2), "0.0.0.0/0", "::0/0")},
		},
		{
			// 匿名 peer 与用户公钥相同:NewServer 按 LoadOrStore 静默丢掉它,
			// 丢掉之后才查重叠 —— 所以它的 0.0.0.0/0 不能让配置失败。
			name:  "anonymous-duplicate-of-user-is-dropped",
			users: []*protocol.User{named("alice", peer(pubHex(2), "10.0.0.2/32"))},
			peers: []*PeerConfig{peer(pubHex(2), "0.0.0.0/0", "::0/0")},
		},
		{
			name:  "anonymous-duplicates-each-other",
			peers: []*PeerConfig{peer(pubHex(2), "0.0.0.0/0"), peer(pubHex(2), "0.0.0.0/0")},
		},
		{
			// NewServer 不查「peer 公钥 == 服务端公钥」(只有 AddUser 查),这里也不能查。
			name:  "peer-key-equals-server-public-key",
			users: []*protocol.User{named("alice", peer(hex.EncodeToString(serverPub[:]), "10.0.0.2/32"))},
		},
		{
			name:    "overlap",
			users:   []*protocol.User{named("alice", peer(pubHex(2), "10.0.0.0/24")), named("bob", peer(pubHex(3), "10.0.0.3/32"))},
			wantErr: true,
		},
		{
			name:    "overlap-with-anonymous",
			users:   []*protocol.User{named("alice", peer(pubHex(2), "10.0.0.2/32"))},
			peers:   []*PeerConfig{peer(pubHex(4), "0.0.0.0/0", "::0/0")},
			wantErr: true,
		},
		{
			name:    "non-canonical",
			users:   []*protocol.User{named("alice", peer(pubHex(2), "10.0.0.5/24"))},
			wantErr: true,
		},
		{
			name:    "empty-allowed-ips",
			users:   []*protocol.User{named("alice", peer(pubHex(2)))},
			wantErr: true,
		},
		{
			name:    "duplicate-public-key",
			users:   []*protocol.User{named("alice", peer(pubHex(2), "10.0.0.2/32")), named("bob", peer(pubHex(2), "10.0.0.3/32"))},
			wantErr: true,
		},
		{
			// 公钥比较的是解码后的字节:同一把 hex 公钥大小写不同也是同一个 peer。
			name:    "duplicate-public-key-hex-case",
			users:   []*protocol.User{named("alice", peer(upper, "10.0.0.2/32")), named("bob", peer(lower, "10.0.0.3/32"))},
			wantErr: true,
		},
		{
			name:    "duplicate-email",
			users:   []*protocol.User{named("alice", peer(pubHex(2), "10.0.0.2/32")), named("alice", peer(pubHex(3), "10.0.0.3/32"))},
			wantErr: true,
		},
		{
			// 上游把建设备挪到 Start 之后,这两类在 NewServer 里不再被 IPC 拦下,改由 validatePeerParams 提前拒。
			name:    "psk-not-32-bytes",
			users:   []*protocol.User{named("alice", &PeerConfig{PublicKey: pubHex(2), AllowedIps: []string{"10.0.0.2/32"}, PreSharedKey: strings.Repeat("ab", 15)})},
			wantErr: true,
		},
		{
			name:    "keepalive-over-uint16",
			users:   []*protocol.User{named("alice", &PeerConfig{PublicKey: pubHex(2), AllowedIps: []string{"10.0.0.2/32"}, KeepAlive: "70000"})},
			wantErr: true,
		},
		{
			name:  "psk-and-keepalive-ok",
			users: []*protocol.User{named("alice", &PeerConfig{PublicKey: pubHex(2), AllowedIps: []string{"10.0.0.2/32"}, PreSharedKey: strings.Repeat("ab", 32), KeepAlive: "25"})},
		},
		{
			// 被丢弃的重复匿名 peer 进不了设备,参数不查(与合并上游前一致)。
			name:  "dropped-anonymous-duplicate-params-unchecked",
			users: []*protocol.User{named("alice", peer(pubHex(2), "10.0.0.2/32"))},
			peers: []*PeerConfig{{PublicKey: pubHex(2), AllowedIps: []string{"0.0.0.0/0"}, PreSharedKey: "abcd", KeepAlive: "70000"}},
		},
		{
			name:    "unparsable-allowed-ip",
			users:   []*protocol.User{named("alice", peer(pubHex(2), "10.0.0.300/32"))},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conf := &DeviceConfig{SecretKey: pubHex(1), Users: tc.users}
			validateErr := ValidateDeviceUsers(append(append([]*protocol.User(nil), tc.users...), anonymous(tc.peers)...))
			_, loadErr := newTestServer(t, conf, tc.peers...)
			if (validateErr != nil) != (loadErr != nil) {
				t.Fatalf("ValidateDeviceUsers err=%v but loadUsers err=%v: the two must agree", validateErr, loadErr)
			}
			if (validateErr != nil) != tc.wantErr {
				t.Fatalf("ValidateDeviceUsers err=%v, wantErr=%v", validateErr, tc.wantErr)
			}
		})
	}
}

func memUser(t *testing.T, email string, p *PeerConfig) *protocol.MemoryUser {
	t.Helper()
	mu, err := named(email, p).ToMemoryUser()
	if err != nil {
		t.Fatalf("ToMemoryUser: %v", err)
	}
	return mu
}

func newServerWithUsers(t *testing.T, users ...*protocol.User) *Server {
	t.Helper()
	s, err := newTestServer(t, &DeviceConfig{SecretKey: pubHex(1), Users: users})
	if err != nil {
		t.Fatalf("loadUsers: %v", err)
	}
	return s
}

// addUser 按上游 AddUser 的顺序:先过 checkNewUser,通过了才下发并落表(设备下发这里省略)。
func addUser(s *Server, u *protocol.MemoryUser) error {
	if err := s.checkNewUser(u); err != nil {
		return err
	}
	s.users.Store(u.Account.(*MemoryAccount).Pub, u)
	return nil
}

func removeUser(s *Server, email string) {
	if u := s.GetUser(context.Background(), email); u != nil {
		s.users.Delete(u.Account.(*MemoryAccount).Pub)
	}
}

// 同一 email 再加一个 peer(换密钥时先加后删):RemoveUser(email) 之后只删得掉一个,
// 另一个继续以同一身份在线计费。必须拒绝,且不能已经落表。
func TestAddUserRejectsDuplicateEmail(t *testing.T) {
	ctx := context.Background()
	s := newServerWithUsers(t, named("alice", peer(pubHex(2), "10.0.0.2/32")))

	if err := addUser(s, memUser(t, "alice", peer(pubHex(3), "10.0.0.3/32"))); err == nil {
		t.Fatal("AddUser with an existing email must fail")
	}
	if got := s.GetUsersCount(ctx); got != 1 {
		t.Fatalf("GetUsersCount = %d, want 1", got)
	}
	if u := s.GetUser(ctx, "alice"); u == nil || u.Account.(*MemoryAccount).Pub[0] != 0x22 {
		t.Fatalf("alice must keep her original key, got %v", u)
	}

	// 其它 email 不受影响;匿名(空 email)peer 不参与 email 查重。
	if err := addUser(s, memUser(t, "bob", peer(pubHex(4), "10.0.0.4/32"))); err != nil {
		t.Fatalf("AddUser(bob): %v", err)
	}
	if err := addUser(s, memUser(t, "", peer(pubHex(5), "10.0.0.5/32"))); err != nil {
		t.Fatalf("AddUser(anonymous #1): %v", err)
	}
	if err := addUser(s, memUser(t, "", peer(pubHex(6), "10.0.0.6/32"))); err != nil {
		t.Fatalf("AddUser(anonymous #2): %v", err)
	}
	if got := s.GetUsersCount(ctx); got != 4 {
		t.Fatalf("GetUsersCount = %d, want 4", got)
	}
}

// 同一公钥重复添加必须拒绝:设备会把它当成同一个 peer,内存表与设备漂移。
func TestAddUserRejectsDuplicatePublicKey(t *testing.T) {
	s := newServerWithUsers(t, named("alice", peer(pubHex(2), "10.0.0.2/32")))
	if err := addUser(s, memUser(t, "bob", peer(pubHex(2), "10.0.0.3/32"))); err == nil {
		t.Fatal("expected duplicate public key to be rejected")
	}
}

// 换密钥的正确顺序是先 RemoveUser 再 AddUser:同 email、同地址、新公钥必须能加回去。
func TestRemoveThenAddRotatesKeyForSameEmail(t *testing.T) {
	ctx := context.Background()
	s := newServerWithUsers(t,
		named("alice", peer(pubHex(2), "10.0.0.2/32", "fd00::2/128")),
		named("bob", peer(pubHex(3), "10.0.0.3/32")),
	)

	removeUser(s, "alice")
	if err := addUser(s, memUser(t, "alice", peer(pubHex(7), "10.0.0.2/32", "fd00::2/128"))); err != nil {
		t.Fatalf("AddUser after RemoveUser: %v", err)
	}
	u := s.GetUserByAddr(ctx, netip.MustParseAddr("10.0.0.2"))
	if u == nil || u.Email != "alice" || u.Account.(*MemoryAccount).Pub[0] != 0x77 {
		t.Fatalf("10.0.0.2 must resolve to alice with the new key, got %v", u)
	}
	if got := s.GetUsersCount(ctx); got != 2 {
		t.Fatalf("GetUsersCount = %d, want 2", got)
	}
}

// AddUser 走的仍是同一套地址校验:与现有用户重叠必须拒绝。
func TestAddUserRejectsOverlap(t *testing.T) {
	s := newServerWithUsers(t, named("alice", peer(pubHex(2), "10.0.0.2/32")))
	if err := addUser(s, memUser(t, "bob", peer(pubHex(3), "10.0.0.0/24"))); err == nil {
		t.Fatal("expected overlap to be rejected")
	}
}
