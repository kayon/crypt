package crypt

type BlockMode uint8

const (
	MODE_CBC BlockMode = iota
	MODE_CFB
	MODE_CTR
	MODE_OFB
	MODE_GCM
	MODE_ECB
)

func (mode BlockMode) Not(modes ...BlockMode) bool {
	for _, m := range modes {
		if m == mode {
			return false
		}
	}
	return true
}

func (mode BlockMode) Has(modes ...BlockMode) bool {
	return !mode.Not(modes...)
}

func (mode BlockMode) String() string {
	switch mode {
	case MODE_CBC:
		return "CBC"
	case MODE_CFB:
		return "CFB"
	case MODE_CTR:
		return "CTR"
	case MODE_OFB:
		return "OFB"
	case MODE_GCM:
		return "GCM"
	case MODE_ECB:
		return "ECB"
	}
	return ""
}
