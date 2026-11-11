# wendynet-display

Same as [wendynet-wifi](../wendynet-wifi), and also shows the latest connection info on an SSD1306 128x64 I2C display at address 0x3C, such as the one on the Seeed XIAO expansion board.

The display shows the Wi-Fi address, the router address, and the connection state or last error wrapped over the remaining lines.

Put the same DER files as wendynet-wifi in `creds/`. They are not committed.

```
tinygo flash -target xiao-esp32c3 -tags lcrypto_nop384,lcrypto_noed25519,lcrypto_norsa -ldflags="-X main.ssid=SSID -X main.password=PASS" -monitor ./examples/wendynet-display
```

The display uses the board `SDA_PIN` and `SCL_PIN`.
