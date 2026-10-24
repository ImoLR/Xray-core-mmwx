package wireguard

// SetKernelTunDevicePathForTest 换掉内核 TUN 设备节点路径,返回还原函数。
func SetKernelTunDevicePathForTest(p string) func() {
	old := kernelTunDevicePath
	kernelTunDevicePath = p
	return func() { kernelTunDevicePath = old }
}
