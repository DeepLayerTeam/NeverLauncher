package repository

func effectiveBridgeCapacity0288(signed int, operator *int) int {
	if operator == nil {
		return signed
	}
	if signed == 0 || *operator < signed {
		return *operator
	}
	return signed
}
