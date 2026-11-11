//go:build tinygo

package main

import (
	"image/color"
	"machine"
	"strings"

	"tinygo.org/x/drivers/ssd1306"
	"tinygo.org/x/tinyfont"
	"tinygo.org/x/tinyfont/proggy"
)

// The 6 pixel wide font fits 21 columns and 6 rows on the 128x64 display.
const (
	cols = 21
	rows = 6
)

var (
	display  *ssd1306.Device
	localIP  string
	routerIP string
	status   string
	white    = color.RGBA{255, 255, 255, 255}
)

// initDisplay uses the SSD1306 at address 0x3C on the XIAO expansion board I2C pins.
func initDisplay() {
	machine.I2C0.Configure(machine.I2CConfig{Frequency: 400 * machine.KHz, SDA: machine.SDA_PIN, SCL: machine.SCL_PIN})
	display = ssd1306.NewI2C(machine.I2C0)
	display.Configure(ssd1306.Config{Width: 128, Height: 64, Address: 0x3C})
	display.ClearDisplay()
}

func state(text string) {
	println("state", text)
	status = text
	display.ClearBuffer()
	row := 0
	draw := func(s string) {
		if row < rows {
			tinyfont.WriteLine(display, &proggy.TinySZ8pt7b, 0, int16(8+10*row), s, white)
			row++
		}
	}
	draw("ip " + localIP)
	draw("rtr " + routerIP)
	for _, s := range wrap(status) {
		draw(s)
	}
	display.Display()
}

// wrap splits text into lines of at most cols characters, breaking at spaces when it can.
func wrap(text string) []string {
	var out []string
	for len(text) > cols {
		i := strings.LastIndexByte(text[:cols+1], ' ')
		if i <= 0 {
			i = cols
		}
		out = append(out, text[:i])
		text = strings.TrimLeft(text[i:], " ")
	}
	return append(out, text)
}
