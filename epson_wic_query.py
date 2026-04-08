#!/usr/bin/env python3
"""
Epson Waste Ink Counter Reset Utility
Protocol fully reverse-engineered from Wireshark captures of WIC Reset Utility.
Tested on: Epson L1250 Series (04B8:130A)

Commands:
    --query            Read all counters, show status (no writes)
    --reset            Full reset to 0% — clears all pad counters
    --demo-reset       Reset to ~80% exactly as WIC demo does (sets demo-used flag)
    --clear-demo-flag  Clear the demo-used flag (allows demo reset to be used again)
    --list             List USB devices
    --verbose          Show raw USB bytes

Requirements:
    sudo apt install python3-usb libusb-1.0-0
    Run as root, or:
      echo 'SUBSYSTEM=="usb", ATTRS{idVendor}=="04b8", MODE="0666"' | \\
        sudo tee /etc/udev/rules.d/99-epson.rules && sudo udevadm control --reload-rules
"""

import sys
import time
import argparse

try:
    import usb.core
    import usb.util
except ImportError:
    print("ERROR: pyusb not installed.  sudo apt install python3-usb")
    sys.exit(1)

# ─────────────────────────────────────────────────────────
# Protocol constants  (confirmed from 3 Wireshark captures)
# ─────────────────────────────────────────────────────────

EPSON_VID = 0x04B8

EJL_INIT = bytes.fromhex("0000001b0140454a4c20313238342e340a40454a4c0a40454a4c0a")

HANDSHAKE = [
    bytes.fromhex("0000000801000010"),
    bytes.fromhex("000000110100094550534f4e2d4354524c"),
    bytes.fromhex("000000110100010202ffffffff00000000"),
    bytes.fromhex("0000000d01000402020001ffff"),
    bytes.fromhex("0000000b01000302020001"),
]

ACK_A    = bytes.fromhex("0000000d01000402020001ffff")
ACK_B    = bytes.fromhex("0000000b01000302020001")
TEARDOWN = [
    bytes.fromhex("000000090100020202"),
    bytes.fromhex("00000007010008"),
]

VERSION_QUERY = bytes.fromhex("0202000b00007669010000")

# Read  (17B): 02 02 00 11 00 00 7c7c 0700 4a3641be a0 <reg_lo> <reg_hi>
READ_PREFIX  = bytes.fromhex("0202001100007c7c07004a3641bea0")

# Write (26B): 02 02 00 1a 00 00 7c7c 1000 4a3642bd 21 <reg_lo> <reg_hi> <value> <8-byte tail>
WRITE_PREFIX = bytes.fromhex("0202001a00007c7c10004a3642bd21")
WRITE_TAIL   = bytes.fromhex("4e62736a63627a62")

# Commit: read 0x0100 then write 0x0100=0x00 — flushes EEPROM
COMMIT_ADDR  = 0x0100
COMMIT_VALUE = 0x00

def build_read(address: int) -> bytes:
    return READ_PREFIX + bytes([address & 0xFF, (address >> 8) & 0xFF])

def build_write(address: int, value: int) -> bytes:
    return WRITE_PREFIX + bytes([address & 0xFF, (address >> 8) & 0xFF, value & 0xFF]) + WRITE_TAIL

def parse_ee(data: bytes) -> int | None:
    """Parse EE:XXYYZZ; — returns the low byte (actual stored value)."""
    try:
        s = data.decode("ascii", errors="replace")
        i = s.find("EE:")
        j = s.find(";", i)
        if i != -1 and j != -1:
            return int(s[i+3:j], 16) & 0xFF
    except Exception:
        pass
    return None

def parse_ok(data: bytes) -> bool:
    return b"OK" in data

# ─────────────────────────────────────────────────────────
# Register definitions
# ─────────────────────────────────────────────────────────

# Capacity block registers — these halt printing when too high
CAPACITY_REGS = [0x00FC, 0x00FD, 0x00FE]

# Lifetime counters — WIC display % is based on these (read-only for display)
LIFETIME_REGS = [0x0644, 0x0645, 0x0646, 0x0647, 0x0648,
                 0x0649, 0x064A, 0x064B, 0x064C, 0x064D]
LIFETIME_MAX  = 513454   # model-specific max for L1250; 410712/513454 = 79.99%

# Demo-used flag registers — printer firmware checks these before allowing demo reset
DEMO_FLAG_REGS  = [0x0036, 0x0037, 0x00FF]
DEMO_FLAG_VALUE = 0x5E   # value WIC stamps after demo use

# Main pad counter registers
PAD_REGS = [0x002F, 0x0030, 0x0031, 0x0032, 0x0033]

# Ancillary registers WIC also writes during demo reset (exact values from capture)
ANCILLARY_REGS = [0x001C, 0x0034, 0x0035]

# ── Reset operation definitions ────────────────────────────────────────────

# Full reset to 0%: zero all pad counters + capacity blocks
FULL_RESET_WRITES = {
    0x001C: 0x00,
    0x002F: 0x00,
    0x0030: 0x00,
    0x0031: 0x00,
    0x0032: 0x00,
    0x0033: 0x00,
    0x0034: 0x00,
    0x0035: 0x00,
    0x00FC: 0x00,
    0x00FD: 0x00,
    0x00FE: 0x00,
}

# Demo reset to ~80%: exact values captured from WIC demo session
# Also stamps demo-used flag (0x0036, 0x0037, 0x00FF = 0x5E)
DEMO_RESET_WRITES = {
    0x001C: 0x00,
    0x002F: 0x00,
    0x0030: 0xD4,
    0x0031: 0x13,
    0x0032: 0xAC,
    0x0033: 0x0A,
    0x0034: 0x00,
    0x0035: 0x00,
    0x0036: 0x5E,   # demo-used flag
    0x0037: 0x5E,   # demo-used flag
    0x00FC: 0x10,
    0x00FD: 0x04,
    0x00FE: 0x00,
    0x00FF: 0x5E,   # demo-used flag
}

# Clear demo flag: write 0x00 to flag registers so printer allows another demo
CLEAR_FLAG_WRITES = {
    0x0036: 0x00,
    0x0037: 0x00,
    0x00FF: 0x00,
}

# ─────────────────────────────────────────────────────────
# USB communication
# ─────────────────────────────────────────────────────────

class EpsonCtrl:
    def __init__(self, vid: int, pid: int, verbose: bool = False):
        self.vid      = vid
        self.pid      = pid
        self.verbose  = verbose
        self.dev      = None
        self.ep_out   = None
        self.ep_in    = None
        self._detached = []

    def connect(self) -> bool:
        self.dev = usb.core.find(idVendor=self.vid, idProduct=self.pid)
        if self.dev is None:
            print(f"ERROR: device {self.vid:04X}:{self.pid:04X} not found.")
            return False
        if sys.platform != "win32":
            try:
                for intf in self.dev.get_active_configuration():
                    n = intf.bInterfaceNumber
                    try:
                        if self.dev.is_kernel_driver_active(n):
                            self.dev.detach_kernel_driver(n)
                            self._detached.append(n)
                            if self.verbose:
                                print(f"  detached kernel driver intf {n}")
                    except usb.core.USBError:
                        pass
            except usb.core.USBError:
                pass
        try:
            self.dev.set_configuration()
        except usb.core.USBError:
            pass
        cfg  = self.dev.get_active_configuration()
        intf = cfg[(0, 0)]
        self.ep_out = usb.util.find_descriptor(intf, custom_match=lambda e:
            usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT
            and usb.util.endpoint_type(e.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK)
        self.ep_in = usb.util.find_descriptor(intf, custom_match=lambda e:
            usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN
            and usb.util.endpoint_type(e.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK)
        if not self.ep_out or not self.ep_in:
            print("ERROR: BULK endpoints not found.")
            return False
        if self.verbose:
            print(f"  EP OUT 0x{self.ep_out.bEndpointAddress:02X}  "
                  f"EP IN  0x{self.ep_in.bEndpointAddress:02X}")
        return True

    def _write(self, data: bytes, timeout: int = 2000):
        if self.verbose:
            print(f"  TX {data.hex()}")
        self.ep_out.write(data, timeout=timeout)

    def _read(self, size: int = 64, timeout: int = 2000) -> bytes:
        try:
            data = bytes(self.ep_in.read(size, timeout=timeout))
            if self.verbose:
                print(f"  RX {data.hex()}")
            return data
        except usb.core.USBTimeoutError:
            if self.verbose: print("  RX (timeout)")
            return b""
        except usb.core.USBError as e:
            if self.verbose: print(f"  RX error: {e}")
            return b""

    def _read_until(self, prefix: bytes, max_polls: int = 20) -> bytes:
        for _ in range(max_polls):
            pkt = self._read(size=64, timeout=500)
            if pkt and pkt[:len(prefix)] == prefix:
                return pkt
            if pkt:
                time.sleep(0.005)
        return b""

    def open_channel(self) -> bool:
        try:
            self._write(EJL_INIT);  self._read()
            for cmd in HANDSHAKE:
                self._write(cmd);   self._read()
            return True
        except usb.core.USBError as e:
            print(f"ERROR during handshake: {e}")
            return False

    def read_register(self, address: int) -> int | None:
        try:
            self._write(build_read(address))
            resp = self._read_until(b'\x02\x02')
            self._write(ACK_A); self._read(size=32)
            self._write(ACK_B); self._read(size=32)
            return parse_ee(resp)
        except usb.core.USBError as e:
            if self.verbose: print(f"  USB error reading 0x{address:04X}: {e}")
            return None

    def write_register(self, address: int, value: int) -> bool:
        try:
            self._write(build_write(address, value))
            resp = self._read_until(b'\x02\x02')
            self._write(ACK_A); self._read(size=32)
            self._write(ACK_B); self._read(size=32)
            ok = parse_ok(resp)
            if not ok and self.verbose:
                print(f"  WARNING: no OK for write 0x{address:04X}=0x{value:02X}")
            return ok
        except usb.core.USBError as e:
            if self.verbose: print(f"  USB error writing 0x{address:04X}: {e}")
            return False

    def version_query(self) -> str:
        try:
            self._write(VERSION_QUERY)
            resp = self._read_until(b'\x02\x02')
            self._write(ACK_A); self._read(size=32)
            self._write(ACK_B); self._read(size=32)
            s = resp.decode("ascii", errors="replace")
            if "vi:" in s:
                parts = s.split(":")
                if len(parts) >= 3:
                    return parts[2].rstrip(";\x0c").strip()
        except Exception:
            pass
        return "unknown"

    def commit(self) -> bool:
        """Read 0x0100 then write 0x0100=0x00 to flush EEPROM (exact WIC sequence)."""
        self.read_register(COMMIT_ADDR)   # WIC reads it first (frame 597)
        return self.write_register(COMMIT_ADDR, COMMIT_VALUE)

    def close_channel(self):
        try:
            for cmd in TEARDOWN:
                self._write(cmd); self._read()
        except Exception:
            pass

    def disconnect(self):
        self.close_channel()
        try: usb.util.dispose_resources(self.dev)
        except Exception: pass
        for n in self._detached:
            try: self.dev.attach_kernel_driver(n)
            except Exception: pass

# ─────────────────────────────────────────────────────────
# Display helpers
# ─────────────────────────────────────────────────────────

W="\033[0m"; RED="\033[91m"; YEL="\033[93m"; GRN="\033[92m"
CYN="\033[96m"; BLD="\033[1m"; DIM="\033[2m"
BAR = 30

def _clr(pct):
    return RED if pct >= 90 else YEL if pct >= 70 else GRN

def _bar(pct):
    pct = min(pct, 100)
    n = int(BAR * pct / 100)
    return "[" + "█"*n + "░"*(BAR-n) + f"] {pct:5.1f}%"

def _sep(title=""):
    if title:
        pad = (55 - len(title) - 2) // 2
        print(f"\n{BLD}{'─'*pad} {title} {'─'*(55-pad-len(title)-2)}{W}")
    else:
        print(f"{BLD}{'─'*55}{W}")

def print_status(results: dict):
    """Print a full status table from a results dict {addr: value}."""
    _sep("CAPACITY COUNTERS")
    print(f"  {'(these register values block printing when too high)'}")
    for addr in CAPACITY_REGS:
        val = results.get(addr)
        if val is None:
            print(f"  0x{addr:04X}  {'?':>5}         READ FAILED")
        else:
            pct = val / 0xFF * 100
            c   = _clr(pct)
            print(f"  0x{addr:04X}  {val:>3} (0x{val:02X})  {c}{_bar(pct)}{W}")

    _sep("PAD COUNTERS")
    for addr in PAD_REGS:
        val = results.get(addr)
        if val is None:
            print(f"  0x{addr:04X}  READ FAILED")
        else:
            print(f"  0x{addr:04X}  {val:>3} (0x{val:02X})")

    _sep("LIFETIME COUNTERS  (WIC display %)")
    # Lifetime values are stored as 3-byte big-endian across consecutive registers
    # We read them individually as single bytes; reconstruct the full value
    # by treating the EE response as: addr_hi, addr_lo, value_lo
    # Full 3-byte value = (addr << 8) | value_lo from last read session
    life_vals = []
    for addr in LIFETIME_REGS:
        val = results.get(addr)
        if val is not None:
            # Reconstruct: addr is e.g. 0x0644, val is low byte 0x58
            # Full counter = (0x06 << 16) | (0x44 << 8) | 0x58 = 0x064458
            full = ((addr & 0xFF) << 8) | val | ((addr >> 8) << 16)
            life_vals.append((addr, full))

    if life_vals:
        # Use the first register as the primary display value
        primary = life_vals[0][1]
        pct = primary / LIFETIME_MAX * 100
        c   = _clr(pct)
        print(f"  Primary (0x0644)  {primary:>8}  {c}{_bar(pct)}{W}")
        print(f"  {DIM}(WIC shows this as the main waste ink % — informational only){W}")
        for addr, full in life_vals[1:]:
            print(f"  0x{addr:04X}            {full:>8}")

    _sep("DEMO FLAG REGISTERS")
    all_clear = True
    for addr in DEMO_FLAG_REGS:
        val = results.get(addr)
        if val is None:
            print(f"  0x{addr:04X}  READ FAILED")
        else:
            if val == DEMO_FLAG_VALUE:
                status = f"{YEL}0x{val:02X} — DEMO USED ⚠{W}"
                all_clear = False
            elif val == 0x00:
                status = f"{GRN}0x{val:02X} — clear (demo available){W}"
            else:
                status = f"{CYN}0x{val:02X} — unknown value{W}"
            print(f"  0x{addr:04X}  {status}")
    if all_clear:
        print(f"  {GRN}All flag registers clear — demo reset is available on this printer.{W}")

# ─────────────────────────────────────────────────────────
# Operation helpers
# ─────────────────────────────────────────────────────────

def do_read(ctrl: EpsonCtrl, addrs: list[int]) -> dict:
    results = {}
    for addr in addrs:
        print(f"    0x{addr:04X}...", end=" ", flush=True)
        val = ctrl.read_register(addr)
        results[addr] = val
        print(f"{val} (0x{val:02X})" if val is not None else "FAILED")
    return results

def do_writes(ctrl: EpsonCtrl, writes: dict[int, int], label: str) -> bool:
    """Execute a dict of {address: value} writes in sorted address order."""
    ver = ctrl.version_query()
    print(f"  Printer version: {ver}")
    print(f"  Writing {len(writes)} register(s):")
    all_ok = True
    for addr in sorted(writes.keys()):
        val = writes[addr]
        print(f"    0x{addr:04X} = 0x{val:02X}...", end=" ", flush=True)
        ok = ctrl.write_register(addr, val)
        print(f"{GRN}OK{W}" if ok else f"{RED}FAILED{W}")
        if not ok:
            all_ok = False
    print(f"  Committing to EEPROM...", end=" ", flush=True)
    ok = ctrl.commit()
    print(f"{GRN}OK{W}" if ok else f"{RED}FAILED{W}")
    if not ok:
        all_ok = False
    return all_ok

def confirm(prompt: str) -> bool:
    print(f"\n  {YEL}⚠  {prompt}{W}")
    print(f"  Proceed? [y/N] ", end="")
    try:
        return input().strip().lower() == "y"
    except (EOFError, KeyboardInterrupt):
        return False

def before_after_summary(before: dict, after: dict, addrs: list[int]):
    _sep("BEFORE / AFTER")
    print(f"  {'Register':<8}  {'Before':>12}  {'After':>12}  Result")
    print(f"  {'─'*8}  {'─'*12}  {'─'*12}  {'─'*12}")
    for addr in addrs:
        bv = before.get(addr)
        av = after.get(addr)
        bstr = f"{bv} (0x{bv:02X})" if bv is not None else "?"
        astr = f"{av} (0x{av:02X})" if av is not None else "?"
        if bv is not None and av is not None:
            if av < bv:
                res = f"{GRN}↓ reduced{W}"
            elif av == bv:
                res = f"{DIM}unchanged{W}"
            elif av == 0x5E and addr in DEMO_FLAG_REGS:
                res = f"{YEL}flagged{W}"
            elif av == 0x00 and addr in DEMO_FLAG_REGS:
                res = f"{GRN}cleared{W}"
            else:
                res = f"{CYN}changed{W}"
        else:
            res = "?"
        print(f"  0x{addr:04X}    {bstr:>12}  {astr:>12}  {res}")

# ─────────────────────────────────────────────────────────
# Device discovery
# ─────────────────────────────────────────────────────────

def find_epson() -> usb.core.Device | None:
    devs = list(usb.core.find(find_all=True, idVendor=EPSON_VID))
    if not devs:
        return None
    for dev in devs:
        try:
            for intf in dev.get_active_configuration():
                if intf.bInterfaceClass == 0x07:
                    return dev
        except Exception:
            pass
    return devs[0]

def list_devices():
    print("\nUSB devices:")
    for dev in usb.core.find(find_all=True):
        try:
            prod = usb.util.get_string(dev, dev.iProduct) if dev.iProduct else ""
            tag  = "  ← EPSON" if dev.idVendor == EPSON_VID else ""
            print(f"  {dev.idVendor:04X}:{dev.idProduct:04X}  {prod}{tag}")
        except Exception:
            print(f"  {dev.idVendor:04X}:{dev.idProduct:04X}")
    print()

# ─────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Epson waste ink counter utility — query, reset, demo reset, flag management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 epson_wic_reset.py --query
  sudo python3 epson_wic_reset.py --reset
  sudo python3 epson_wic_reset.py --demo-reset
  sudo python3 epson_wic_reset.py --clear-demo-flag
  sudo python3 epson_wic_reset.py --clear-demo-flag --demo-reset
        """
    )
    ap.add_argument("--query",           action="store_true",
                    help="Read all counters and show status (no writes)")
    ap.add_argument("--reset",           action="store_true",
                    help="Full reset to 0%% — zero all pad and capacity counters")
    ap.add_argument("--demo-reset",      action="store_true",
                    help="Reset to ~80%% exactly as WIC demo (stamps demo-used flag)")
    ap.add_argument("--clear-demo-flag", action="store_true",
                    help="Clear demo-used flag so demo reset can be used again")
    ap.add_argument("--list",    action="store_true",  help="List USB devices and exit")
    ap.add_argument("--vid",     type=lambda x: int(x,16), default=EPSON_VID)
    ap.add_argument("--pid",     type=lambda x: int(x,16), default=None)
    ap.add_argument("--verbose", action="store_true",  help="Show raw USB bytes")
    args = ap.parse_args()

    if args.list:
        list_devices()
        return

    # Must specify at least one action
    ops = [args.query, args.reset, args.demo_reset, args.clear_demo_flag]
    if not any(ops):
        ap.print_help()
        print(f"\n{YEL}Specify an operation: --query, --reset, --demo-reset, --clear-demo-flag{W}")
        sys.exit(1)

    # Mutually exclusive write operations
    write_ops = [args.reset, args.demo_reset]
    if sum(write_ops) > 1:
        print(f"{RED}ERROR: --reset and --demo-reset are mutually exclusive.{W}")
        sys.exit(1)

    # Find device
    pid = args.pid
    if not pid:
        dev = find_epson()
        if not dev:
            print("No Epson device found. Use --list.")
            sys.exit(1)
        pid = dev.idProduct
        try:
            prod = usb.util.get_string(dev, dev.iProduct) if dev.iProduct else "Unknown"
        except Exception:
            prod = "Unknown"
        print(f"Found: {args.vid:04X}:{pid:04X}  {prod}")

    ctrl = EpsonCtrl(args.vid, pid, verbose=args.verbose)

    print("Connecting...")
    if not ctrl.connect():
        sys.exit(1)

    print("Opening EPSON-CTRL channel...")
    if not ctrl.open_channel():
        ctrl.disconnect()
        sys.exit(1)

    # Registers to read for initial status
    all_read_addrs = PAD_REGS + CAPACITY_REGS + LIFETIME_REGS + DEMO_FLAG_REGS

    # ── STEP 1: Always read current state ─────────────────
    _sep("Step 1: Read current state")
    print("  Reading registers...")
    before = do_read(ctrl, all_read_addrs)
    print_status(before)

    if args.query:
        ctrl.disconnect()
        return

    # ── STEP 2: Operations ────────────────────────────────

    # clear-demo-flag (can be combined with demo-reset)
    if args.clear_demo_flag:
        _sep("Step 2a: Clear demo-used flag")
        flag_vals = {a: before.get(a) for a in DEMO_FLAG_REGS}
        already_clear = all(v == 0x00 for v in flag_vals.values() if v is not None)
        if already_clear:
            print(f"  {GRN}Flag registers are already clear — nothing to do.{W}")
        else:
            print(f"  Will write 0x00 to: "
                  f"{', '.join(f'0x{a:04X}' for a in DEMO_FLAG_REGS)}")
            if not confirm("This clears the demo-used flag. Writes to printer EEPROM."):
                print("  Aborted.")
                ctrl.disconnect()
                return
            print()
            do_writes(ctrl, CLEAR_FLAG_WRITES, "clear-demo-flag")

    # reset or demo-reset
    if args.reset:
        _sep("Step 2b: Full reset to 0%")
        print(f"  Will zero all pad counters and capacity block registers.")
        print(f"  Registers: {', '.join(f'0x{a:04X}' for a in sorted(FULL_RESET_WRITES))}")
        if not confirm("This resets waste ink counters to 0%%. Writes to printer EEPROM."):
            print("  Aborted.")
            ctrl.disconnect()
            return
        print()
        ok = do_writes(ctrl, FULL_RESET_WRITES, "full-reset")
        if not ok:
            print(f"\n  {RED}⚠  One or more writes failed.{W}")

    elif args.demo_reset:
        _sep("Step 2b: Demo reset to ~80%")
        # Check if demo flag is already set (and not cleared above)
        flag_set = any(before.get(a) == DEMO_FLAG_VALUE for a in DEMO_FLAG_REGS)
        if flag_set and not args.clear_demo_flag:
            print(f"  {YEL}⚠  Demo flag is already set on this printer.{W}")
            print(f"     The printer firmware may reject this operation.")
            print(f"     Use --clear-demo-flag first to reset the flag.")
            if not confirm("Attempt demo reset anyway?"):
                print("  Aborted.")
                ctrl.disconnect()
                return
        else:
            print(f"  Will replicate exact WIC demo reset values + stamp demo-used flag.")
        print(f"  Registers: {', '.join(f'0x{a:04X}' for a in sorted(DEMO_RESET_WRITES))}")
        if not confirm("This performs a demo-style reset. Writes to printer EEPROM."):
            print("  Aborted.")
            ctrl.disconnect()
            return
        print()
        ok = do_writes(ctrl, DEMO_RESET_WRITES, "demo-reset")
        if not ok:
            print(f"\n  {RED}⚠  One or more writes failed.{W}")

    # ── STEP 3: Verify ────────────────────────────────────
    _sep("Step 3: Verify — read back")
    print("  Reading registers...")
    after = do_read(ctrl, all_read_addrs)

    ctrl.disconnect()

    # Summary
    changed_addrs = sorted(
        set(list(FULL_RESET_WRITES.keys()) + list(DEMO_RESET_WRITES.keys())
            + list(CLEAR_FLAG_WRITES.keys()))
    )
    before_after_summary(before, after, changed_addrs)

    # Final status
    print_status(after)
    _sep()
    print()

if __name__ == "__main__":
    main()
