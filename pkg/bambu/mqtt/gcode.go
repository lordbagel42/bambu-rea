package mqtt

import (
	"math"
	"strconv"
	"strings"
)

// Default feed rates from BblCommandEncoderKt (mm/min).
const (
	DefaultAxisFeedRateXY = 9000.0
	DefaultAxisFeedRateZ  = 1800.0
)

// MoveAxisParams are relative moves in millimetres; nil axes are left alone.
// FeedRate overrides the app's default (9000 for any XY move, 1800 for Z only).
type MoveAxisParams struct {
	X, Y, Z  *float64
	FeedRate *float64
}

// HomeAxesParams selects which axes G28 homes.
type HomeAxesParams struct {
	X, Y, Z bool
}

// MoveAxis builds the print/gcode_line command the app sends for the jog pad:
// soft endstops off, push reference mode, relative G1, pop, endstops restored.
func MoveAxis(a MoveAxisParams) Command {
	var words []string
	if a.X != nil {
		words = append(words, "X"+fmtGcode(*a.X))
	}
	if a.Y != nil {
		words = append(words, "Y"+fmtGcode(*a.Y))
	}
	if a.Z != nil {
		words = append(words, "Z"+fmtGcode(*a.Z))
	}
	feed := a.FeedRate
	if feed == nil {
		feed = defaultAxisFeedRate(a.X, a.Y, a.Z)
	}
	if feed != nil {
		words = append(words, "F"+fmtGcode(*feed))
	}
	g := "M211 S\nM211 X1 Y1 Z1\nM1002 push_ref_mode\nG91\nG1 " + strings.Join(words, " ") + "\nM1002 pop_ref_mode\nM211 R"
	return GcodeLine(GcodeLineParams{Param: g})
}

// HomeAxes builds the print/gcode_line command for "G28 X Y Z" with the selected axes.
func HomeAxes(a HomeAxesParams) Command {
	var words []string
	if a.X {
		words = append(words, "X")
	}
	if a.Y {
		words = append(words, "Y")
	}
	if a.Z {
		words = append(words, "Z")
	}
	return GcodeLine(GcodeLineParams{Param: "G28 " + strings.Join(words, " ")})
}

func defaultAxisFeedRate(x, y, z *float64) *float64 {
	if x == nil && y == nil && z == nil {
		return nil
	}
	f := DefaultAxisFeedRateXY
	if x == nil && y == nil {
		f = DefaultAxisFeedRateZ
	}
	return &f
}

// fmtGcode mirrors BblCommandEncoderKt.fmtGcode: integral values print without a
// fraction, everything else uses the shortest decimal representation.
func fmtGcode(v float64) string {
	if v == math.Floor(v) && !math.IsInf(v, 0) {
		return strconv.Itoa(int(v))
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}
