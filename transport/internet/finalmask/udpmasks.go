package finalmask

// HasUDPMasks reports whether fm changes the datagrams it sends and receives.
// Without UDP masks, DialUDP and ListenPacket give the plain socket.
func (fm *FinalMask) HasUDPMasks() bool {
	return fm != nil && len(fm.udpMasks) > 0
}
