package daemon

import "fmt"

func (s *StartedService) TransferTotals() string {
	v := s.readStatus()
	return fmt.Sprintf("[%d,%d]", v.UplinkTotal, v.DownlinkTotal)
}
