package announce

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

var speedUnits = [...]string{"B/s", "KB/s", "MB/s", "GB/s", "TB/s", "PB/s"}

// Keep the existing binary (1024) conversion and familiar MB/s labels.
func formatSpeed(bytesPerSecond float64) string {
	unit := 0
	for math.Abs(bytesPerSecond) >= 1024 && unit < len(speedUnits)-1 {
		bytesPerSecond /= 1024
		unit++
	}
	return fmt.Sprintf("%.2f%s", bytesPerSecond, speedUnits[unit])
}

// Event data from the master already includes a unit. Normalize presentation
// without changing numeric protocol fields such as speed_kbps.
func scaleSpeed(value string) string {
	trimmed := strings.TrimSpace(value)
	// Match longest suffixes first: KB/s also ends with B/s.
	for unit := len(speedUnits) - 1; unit >= 0; unit-- {
		if !strings.HasSuffix(trimmed, speedUnits[unit]) {
			continue
		}
		number, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(trimmed, speedUnits[unit])), 64)
		if err != nil || math.IsNaN(number) || math.IsInf(number, 0) {
			return value
		}
		return formatSpeed(number * math.Pow(1024, float64(unit)))
	}
	return value
}
