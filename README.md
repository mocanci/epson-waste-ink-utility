# Epson Waste Ink Counter Utility

A reverse-engineered command-line tool for reading and resetting waste ink pad counters on Epson printers via USB, without needing WIC Reset Utility or any proprietary software.

Tested on **Epson L1250** (USB `04B8:130A`). Should work on other Epson L-series printers that use the `EPSON-CTRL` USB protocol.

---

## Background

Epson inkjet printers track how much ink has been absorbed by the internal waste ink pads. When the counter reaches 100%, the printer locks up and refuses to print — even if the physical pads are not actually saturated. Normally you need a paid utility (WIC Reset Utility, SSC Service Utility, etc.) to reset these counters.

This tool was built by capturing USB traffic between WIC Reset Utility and an Epson L1250, then fully reverse-engineering the `EPSON-CTRL` binary protocol that Epson uses over USB bulk transfers. No Epson SDK or proprietary code is used.

### How it works

The printer exposes a register-based read/write interface over USB bulk transfers using a protocol called `EPSON-CTRL`. The tool opens this channel (via an EJL handshake), reads or writes specific EEPROM registers, then commits the changes.

There are two distinct register groups relevant to the waste ink counter:

| Register group | Addresses | Purpose |
|---|---|---|
| Capacity block | `0x00FC`, `0x00FD`, `0x00FE` | **Trigger the print lock** when too high |
| Lifetime counters | `0x0644`–`0x064D` | What WIC displays as the main % (informational) |
| Pad counters | `0x002F`–`0x0033` | Cumulative pad usage counts |
| Demo-used flag | `0x0036`, `0x0037`, `0x00FF` | Marks that WIC's one-time demo code has been used |

Resetting the capacity block registers (`0x00FC`–`0x00FE`) to `0x00` is what unblocks the printer. The lifetime counter % displayed in WIC is informational and reflects real physical ink absorbed — it is not what causes the lockout.

---

## Requirements

### Linux

```bash
sudo apt install python3-usb libusb-1.0-0
```

USB access requires either running as root, or adding a udev rule:

```bash
echo 'SUBSYSTEM=="usb", ATTRS{idVendor}=="04b8", MODE="0666"' | \
  sudo tee /etc/udev/rules.d/99-epson.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

### Windows

```bash
pip install pyusb
```

Also install [Zadig](https://zadig.akeo.ie/) and replace the Epson USB driver with **WinUSB** or **libusb-win32** for your printer device.

### macOS

```bash
brew install libusb
pip install pyusb
```

---

## Installation

```bash
git clone https://github.com/yourusername/epson-wic-reset
cd epson-wic-reset
```

No further installation needed — it's a single Python file with one dependency (`pyusb`).

---

## Usage

### Read counter status (safe — no writes)

```bash
sudo python3 epson_wic_reset.py --query
```

Shows all register values, capacity counter fill levels, lifetime %, and whether the demo flag is set.

Example output:

```
Found: 04B8:130A  L1250 Series
Connecting...
Opening EPSON-CTRL channel...

──── CAPACITY COUNTERS ───────────────────────────────
  (these register values block printing when too high)
  0x00FC   16 (0x10)  [█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░]   6.3%
  0x00FD    4 (0x04)  [░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░]   1.6%
  0x00FE    0 (0x00)  [░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░]   0.0%

──── PAD COUNTERS ────────────────────────────────────
  0x002F    0 (0x00)
  0x0030  212 (0xD4)
  ...

──── LIFETIME COUNTERS (WIC display %) ───────────────
  Primary (0x0644)    410712  [██████████████████████░░░░░░░░]  79.9%

──── DEMO FLAG REGISTERS ─────────────────────────────
  0x0036  0x5E — DEMO USED ⚠
  0x0037  0x5E — DEMO USED ⚠
  0x00FF  0x5E — DEMO USED ⚠
```

---

### Full reset to 0%

Zeros all pad and capacity block counters. This is the most complete reset — WIC will show ~80% (the lifetime counter is unaffected as it reflects actual physical ink absorbed) but the printer will be unblocked.

```bash
sudo python3 epson_wic_reset.py --reset
```

Prompts for confirmation before writing anything.

---

### Demo-style reset to ~80%

Replicates the exact register values that WIC Reset Utility writes during a demo reset. Sets counters to ~80% of their scale and stamps the demo-used flag (`0x5E`) on the printer — the same way WIC marks that its one-time demo code has been consumed.

```bash
sudo python3 epson_wic_reset.py --demo-reset
```

> ⚠ This stamps the demo-used flag. If you later want to use WIC's demo code feature again, clear the flag first (see below).

---

### Clear the demo-used flag

WIC's demo reset is advertised as a one-time use per printer. It enforces this by writing `0x5E` to three flag registers on the printer's EEPROM. Clearing these registers allows the demo reset to be used again.

```bash
sudo python3 epson_wic_reset.py --clear-demo-flag
```

---

### Combined: clear flag and demo-reset in one step

```bash
sudo python3 epson_wic_reset.py --clear-demo-flag --demo-reset
```

Clears the demo-used flag, then immediately performs the demo-style reset. Effectively makes the WIC demo reset reusable.

---

### Other options

```bash
# List all USB devices (to find your printer's PID)
sudo python3 epson_wic_reset.py --list

# Specify printer manually if auto-detect fails
sudo python3 epson_wic_reset.py --query --pid 0x130A

# Show raw USB bytes (for debugging or capturing a different model)
sudo python3 epson_wic_reset.py --query --verbose
```

---

## Compatibility

This tool was developed and tested on an **Epson L1250**. The `EPSON-CTRL` protocol and register layout are expected to be the same or very similar across the Epson EcoTank / L-series range, but register addresses and maximum values may differ between models.

If you have a different Epson printer:

1. Install Wireshark + [USBPcap](https://desowin.org/usbpcap/) (Windows) or enable `usbmon` (Linux)
2. Capture a session of WIC reading the counters
3. Open an issue with the `.pcapng` file and I can decode the register map for your model

### Known working models

| Model | USB ID | Status |
|---|---|---|
| Epson L1250 | `04B8:130A` | ✅ Tested |

---

## Protocol reference

The `EPSON-CTRL` protocol runs over standard USB printer class bulk transfers.

### Session structure

```
1. EJL handshake    host → printer   @EJL 1284.4 init
2. Channel open     host ↔ printer   5-packet EPSON-CTRL negotiation
3. Read/write loop  host ↔ printer   register read or write commands
4. Commit           host → printer   flush EEPROM (write 0x0100 = 0x00)
5. Teardown         host → printer   close channel
```

### Read command (17 bytes)

```
02 02 00 11  00 00  7C 7C  07 00  4A 36 41 BE  A0  <reg_lo> <reg_hi>
─────────── ──────  ─────  ─────  ──────────── ──  ────────────────
header       flags  magic  magic2  device ID   cmd  address (LE)
```

Response: `@BDC PS\r\nEE:XXYYZZ;\x0c` where `ZZ` is the register value byte.

### Write command (26 bytes)

```
02 02 00 1A  00 00  7C 7C  10 00  4A 36 42 BD  21  <reg_lo> <reg_hi>  <value>  4E 62 73 6A 63 62 7A 62
─────────── ──────  ─────  ─────  ──────────── ──  ────────────────── ───────  ────────────────────────
header       flags  magic  magic2  write token  cmd  address (LE)      1 byte   constant tail
```

Response: `||:42:OK;\x0c`

The device ID (`4A 36 41 BE` for reads, `4A 36 42 BD` for writes) was confirmed stable across multiple USB reconnections — it is a device identifier, not a session token.

---

## Safety notes

- **Always run `--query` first** and verify the output before writing anything.
- Each write operation prompts for confirmation.
- Writes target EEPROM. Incorrect values won't brick the printer — the worst case is the counter being at an unexpected value, which can be corrected by running the tool again.
- The lifetime counters (`0x0644`–`0x064D`) are not reset by any operation in this tool. They reflect the real total ink pumped through the printer since manufacture and serve as a wear indicator. Zeroing them would misrepresent the printer's actual wear state.
- This tool does not affect print quality, ink levels, or any other printer function.

---

## License

MIT License. See `LICENSE` for details.

---

## Contributing

Pull requests welcome. If you have a capture from a different Epson model, open an issue — adding support for new models is straightforward once the register map is known.
