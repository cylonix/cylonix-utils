package utils

func ShortString(str string) string {
	return ShortStringN(str, 5)
}

func ShortStringN(str string, n int) string {
	if len(str) > n {
		str = str[:n]
	}
	return "[" + str + "]"
}
