import sys, struct, math, time
from collections import deque

import numpy as np
from PySide6 import QtCore, QtWidgets
import pyqtgraph as pg
import serial
import serial.tools.list_ports

MAGIC = b"\xCF\x42"

# Rolling windows
WIN_BYTES = 4096
WIN_ADC = 512


# ---------------- Metrics ----------------
def shannon_entropy_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(data)
    return float(-(p * np.log2(p)).sum())

def min_entropy_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    pmax = counts.max() / len(data)
    return float(-math.log2(pmax)) if pmax > 0 else 0.0

def freq_monobit(data: bytes) -> float:
    """NIST-ish: proportion of 1s in bitstream (0.5 ideal)."""
    if not data:
        return 0.0
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    return float(bits.mean())

def runs_test(data: bytes) -> float:
    """NIST-ish: run count normalized (rough). Returns |z|-ish."""
    if not data:
        return 0.0
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    if len(bits) < 2:
        return 0.0
    runs = 1 + np.sum(bits[1:] != bits[:-1])
    n = len(bits)
    exp_runs = 1 + (n - 1) / 2
    var_runs = (n - 2) / 4
    z = (runs - exp_runs) / math.sqrt(max(var_runs, 1e-9))
    return float(abs(z))

def serial_correlation(data: bytes) -> float:
    """Correlation between successive bytes (0 ideal-ish)."""
    if len(data) < 2:
        return 0.0
    x = np.frombuffer(data, dtype=np.uint8).astype(np.float32)
    x0 = x[:-1]
    x1 = x[1:]
    if x0.std() < 1e-6 or x1.std() < 1e-6:
        return 1.0
    return float(np.corrcoef(x0, x1)[0, 1])

def chi_square_256(data: bytes) -> float:
    """Chi-square uniformity statistic (lower is better)."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    exp = len(data) / 256.0
    return float(((counts - exp) ** 2 / max(exp, 1e-9)).sum())

def crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc


# ---------------- Serial Reader ----------------
class ChaosFieldReader(QtCore.QObject):
    packet = QtCore.Signal(dict)
    log = QtCore.Signal(str)

    def __init__(self):
        super().__init__()
        self.ser = None
        self.buf = bytearray()

        # debug counters
        self.rx_total = 0
        self.magic_hits = 0
        self.pkts_ok = 0
        self.pkts_bad_crc = 0
        self.pkts_bad_ver = 0
        self.pkts_short = 0

        self._last_magic_scan_t = time.time()
        self._last_magic_scan_bytes = 0

    def ports(self):
        return list(serial.tools.list_ports.comports())

    def connect(self, port: str, baud: int):
        self.close()

        # Many ESP32 devkits reset when DTR/RTS toggles. We'll keep them low and
        # give the board a moment to reboot and start streaming.
        self.ser = serial.Serial(
            port,
            baudrate=baud,
            timeout=0.05,
            write_timeout=0.05,
            dsrdtr=False,
            rtscts=False,
        )
        try:
            self.ser.dtr = False
            self.ser.rts = False
        except Exception:
            pass

        self.buf.clear()
        self.rx_total = 0
        self.magic_hits = 0
        self.pkts_ok = 0
        self.pkts_bad_crc = 0
        self.pkts_bad_ver = 0
        self.pkts_short = 0

        # Let the board settle (boot + Wi-Fi init) and then clear any boot spew.
        time.sleep(1.2)
        try:
            self.ser.reset_input_buffer()
        except Exception:
            pass

        self.log.emit(f"Connected to {port} @ {baud}. Waiting for MAGIC {MAGIC.hex()}…")

    def close(self):
        if self.ser:
            try:
                self.ser.close()
            except Exception:
                pass
        self.ser = None

    def poll(self):
        if not self.ser:
            return

        try:
            chunk = self.ser.read(4096)
        except Exception as e:
            self.log.emit(f"Serial read error: {e}")
            return

        if chunk:
            self.buf.extend(chunk)
            self.rx_total += len(chunk)

        # Packet formats:
        # Common: magic2 + ver1 + seq4 + flags2
        # v0.1 telemetry: "<HHHHHHHHhH" (10 fields, 20 bytes)
        # v0.3 telemetry: "<HHHHHHHHhHHHH" (13 fields, 26 bytes)
        # then lengths "<HHH" and payloads and crc16

        while True:
            idx = self.buf.find(MAGIC)
            if idx < 0:
                # Periodic "are we seeing anything" hint (helps when baud is wrong)
                now = time.time()
                if now - self._last_magic_scan_t > 1.0:
                    if len(self.buf) > 0 and self.pkts_ok == 0:
                        self.log.emit(
                            f"No MAGIC seen yet. Tip: try a different baud (230400 / 115200) or close Arduino Serial Monitor."
                        )
                    self._last_magic_scan_t = now
                if len(self.buf) > 8192:
                    self.buf = self.buf[-4096:]
                return

            if idx > 0:
                # drop garbage before magic
                del self.buf[:idx]

            # need at least magic2 + ver1
            if len(self.buf) < 3:
                return

            ver = self.buf[2]
            if ver == 0x01:
                tele_fmt = "<HHHHHHHHhH"
            elif ver == 0x03:
                tele_fmt = "<HHHHHHHHhHHHH"
            else:
                # unknown version, resync by one byte
                self.pkts_bad_ver += 1
                del self.buf[0]
                continue

            tele_size = struct.calcsize(tele_fmt)
            min_header = 2 + 1 + 4 + 2 + tele_size + 6  # + lengths

            if len(self.buf) < min_header:
                self.pkts_short += 1
                return

            self.magic_hits += 1

            off = 0
            off += 2  # magic
            ver = self.buf[off]; off += 1
            seq = struct.unpack_from("<I", self.buf, off)[0]; off += 4
            flags = struct.unpack_from("<H", self.buf, off)[0]; off += 2

            tele = struct.unpack_from(tele_fmt, self.buf, off)
            off += tele_size

            adc_len, vn_len, cond_len = struct.unpack_from("<HHH", self.buf, off)
            off += 6

            full_len = off + adc_len + vn_len + cond_len + 2  # + crc
            if len(self.buf) < full_len:
                self.pkts_short += 1
                return

            payload_no_crc = bytes(self.buf[:full_len - 2])
            crc_recv = struct.unpack_from("<H", self.buf, full_len - 2)[0]
            crc_calc = crc16_ccitt(payload_no_crc)

            if crc_recv != crc_calc:
                self.pkts_bad_crc += 1
                # resync: move by one byte and try again
                del self.buf[0]
                continue

            # Extract payloads
            p_off = off
            adc_bytes = self.buf[p_off:p_off + adc_len]; p_off += adc_len
            vn_bytes = bytes(self.buf[p_off:p_off + vn_len]); p_off += vn_len
            cond_bytes = bytes(self.buf[p_off:p_off + cond_len]); p_off += cond_len

            del self.buf[:full_len]

            adc = np.frombuffer(adc_bytes, dtype=np.uint16).copy()

            out = {
                "ver": ver,
                "seq": seq,
                "flags": flags,
                "adc": adc,
                "vn": vn_bytes,
                "cond": cond_bytes,
            }

            # Map telemetry by version
            if ver == 0x01:
                (adc_min, adc_max, adc_mean, adc_sat_low, adc_sat_high,
                 vn_permille, wifi_scan_ms, wifi_nets, wifi_rssi, loop_us) = tele

                out.update({
                    "adc_min": adc_min, "adc_max": adc_max, "adc_mean": adc_mean,
                    "adc_sat_low": adc_sat_low, "adc_sat_high": adc_sat_high,
                    "vn_permille": vn_permille,
                    "wifi_scan_ms": wifi_scan_ms, "wifi_nets": wifi_nets, "wifi_rssi": wifi_rssi,
                    "loop_us": loop_us,
                    "pickup_energy": None, "jitter_span": None, "trng_mix": None
                })
            else:
                (adc_min, adc_max, adc_mean, adc_sat_low, adc_sat_high,
                 vn_permille, wifi_scan_ms, wifi_nets, wifi_rssi,
                 pickup_energy, jitter_span, trng_mix, loop_us) = tele

                out.update({
                    "adc_min": adc_min, "adc_max": adc_max, "adc_mean": adc_mean,
                    "adc_sat_low": adc_sat_low, "adc_sat_high": adc_sat_high,
                    "vn_permille": vn_permille,
                    "wifi_scan_ms": wifi_scan_ms, "wifi_nets": wifi_nets, "wifi_rssi": wifi_rssi,
                    "pickup_energy": pickup_energy, "jitter_span": jitter_span, "trng_mix": trng_mix,
                    "loop_us": loop_us,
                })

            self.pkts_ok += 1
            self.packet.emit(out)


# ---------------- UI ----------------
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Chaos Field Reactor Panel")
        self.resize(1250, 860)

        self.reader = ChaosFieldReader()
        self.reader.packet.connect(self.on_packet)
        self.reader.log.connect(self._log)

        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.reader.poll)
        self.timer.start(20)

        # RX rate timer
        self.rx_timer = QtCore.QTimer(self)
        self.rx_timer.timeout.connect(self._update_rx)
        self.rx_timer.start(500)
        self._rx_last = 0
        self._rx_last_t = QtCore.QElapsedTimer()
        self._rx_last_t.start()

        # Data buffers
        self.adc_trace = deque(maxlen=WIN_ADC)
        self.vn_win = deque(maxlen=WIN_BYTES)
        self.cond_win = deque(maxlen=WIN_BYTES)

        root = QtWidgets.QWidget()
        self.setCentralWidget(root)
        layout = QtWidgets.QVBoxLayout(root)

        # Controls
        ctl = QtWidgets.QHBoxLayout()
        layout.addLayout(ctl)

        self.port_box = QtWidgets.QComboBox()
        self.refresh_btn = QtWidgets.QPushButton("Refresh Ports")
        self.connect_btn = QtWidgets.QPushButton("Connect")
        self.disconnect_btn = QtWidgets.QPushButton("Disconnect")
        self.baud_box = QtWidgets.QComboBox()
        for b in [921600, 460800, 230400, 115200]:
            self.baud_box.addItem(str(b))
        self.baud_box.setCurrentText("921600")

        ctl.addWidget(QtWidgets.QLabel("Port:"))
        ctl.addWidget(self.port_box, 2)
        ctl.addWidget(self.refresh_btn)
        ctl.addWidget(QtWidgets.QLabel("Baud:"))
        ctl.addWidget(self.baud_box)
        ctl.addWidget(self.connect_btn)
        ctl.addWidget(self.disconnect_btn)
        ctl.addStretch(1)

        self.status = QtWidgets.QLabel("DISCONNECTED")
        self.lab_rx = QtWidgets.QLabel("RX: 0 B/s")
        self.lab_pkts = QtWidgets.QLabel("PKTS: ok=0 badcrc=0 badver=0 short=0 magic=0")
        ctl.addWidget(self.status)
        ctl.addWidget(self.lab_rx)
        ctl.addWidget(self.lab_pkts)

        self.refresh_btn.clicked.connect(self.refresh_ports)
        self.connect_btn.clicked.connect(self.do_connect)
        self.disconnect_btn.clicked.connect(self.do_disconnect)

        self.refresh_ports()

        # Theme + plots
        pg.setConfigOptions(antialias=True)
        self._apply_dark_green_theme()

        plots = QtWidgets.QHBoxLayout()
        layout.addLayout(plots, 1)

        self.adc_plot = pg.PlotWidget(title="Pickup ADC Trace")
        self.adc_curve = self.adc_plot.plot(pen=pg.mkPen("#00ff66", width=2))
        self.adc_plot.setYRange(0, 4095)
        plots.addWidget(self.adc_plot, 2)

        self.hist_vn = pg.PlotWidget(title="VN Bytes Histogram")
        self.hist_cond = pg.PlotWidget(title="Conditioned Bytes Histogram")
        self.bar_vn = pg.BarGraphItem(x=np.arange(256), height=np.zeros(256), width=1.0, brush="#00ff66")
        self.bar_cond = pg.BarGraphItem(x=np.arange(256), height=np.zeros(256), width=1.0, brush="#00ffaa")
        self.hist_vn.addItem(self.bar_vn)
        self.hist_cond.addItem(self.bar_cond)
        plots.addWidget(self.hist_vn, 1)
        plots.addWidget(self.hist_cond, 1)

        # Metrics
        metrics = QtWidgets.QGridLayout()
        layout.addLayout(metrics)

        self.lab_ver = QtWidgets.QLabel("-")
        self.lab_seq = QtWidgets.QLabel("-")
        self.lab_wifi = QtWidgets.QLabel("-")
        self.lab_adc = QtWidgets.QLabel("-")
        self.lab_vn = QtWidgets.QLabel("-")
        self.lab_extra = QtWidgets.QLabel("-")

        self.lab_H_vn = QtWidgets.QLabel("-")
        self.lab_H_cond = QtWidgets.QLabel("-")
        self.lab_Hmin_vn = QtWidgets.QLabel("-")
        self.lab_Hmin_cond = QtWidgets.QLabel("-")

        self.lab_freq_vn = QtWidgets.QLabel("-")
        self.lab_runs_vn = QtWidgets.QLabel("-")
        self.lab_corr_vn = QtWidgets.QLabel("-")
        self.lab_chi_vn = QtWidgets.QLabel("-")

        self.lab_freq_cond = QtWidgets.QLabel("-")
        self.lab_runs_cond = QtWidgets.QLabel("-")
        self.lab_corr_cond = QtWidgets.QLabel("-")
        self.lab_chi_cond = QtWidgets.QLabel("-")

        r = 0
        metrics.addWidget(QtWidgets.QLabel("Ver:"), r, 0); metrics.addWidget(self.lab_ver, r, 1)
        metrics.addWidget(QtWidgets.QLabel("Seq:"), r, 2); metrics.addWidget(self.lab_seq, r, 3)
        metrics.addWidget(QtWidgets.QLabel("Wi-Fi scan / nets / RSSI:"), r, 4); metrics.addWidget(self.lab_wifi, r, 5)
        metrics.addWidget(QtWidgets.QLabel("ADC min/max/mean + sat:"), r, 6); metrics.addWidget(self.lab_adc, r, 7)
        metrics.addWidget(QtWidgets.QLabel("VN accept (permille):"), r, 8); metrics.addWidget(self.lab_vn, r, 9)

        r += 1
        metrics.addWidget(QtWidgets.QLabel("Extras (v0.3): energy / jitterSpan / trngMix"), r, 0)
        metrics.addWidget(self.lab_extra, r, 1, 1, 3)

        metrics.addWidget(QtWidgets.QLabel("Shannon H (VN):"), r, 4); metrics.addWidget(self.lab_H_vn, r, 5)
        metrics.addWidget(QtWidgets.QLabel("Shannon H (COND):"), r, 6); metrics.addWidget(self.lab_H_cond, r, 7)
        metrics.addWidget(QtWidgets.QLabel("Min-Entropy (VN):"), r, 8); metrics.addWidget(self.lab_Hmin_vn, r, 9)

        r += 1
        metrics.addWidget(QtWidgets.QLabel("Min-Entropy (COND):"), r, 0); metrics.addWidget(self.lab_Hmin_cond, r, 1)
        metrics.addWidget(QtWidgets.QLabel("VN tests: freq/runs/corr/chi"), r, 2)
        metrics.addWidget(self.lab_freq_vn, r, 3)
        metrics.addWidget(self.lab_runs_vn, r, 4)
        metrics.addWidget(self.lab_corr_vn, r, 5)
        metrics.addWidget(self.lab_chi_vn, r, 6)

        metrics.addWidget(QtWidgets.QLabel("COND tests: freq/runs/corr/chi"), r, 7)
        metrics.addWidget(self.lab_freq_cond, r, 8)
        metrics.addWidget(self.lab_runs_cond, r, 9)

        r += 1
        metrics.addWidget(self.lab_corr_cond, r, 0)
        metrics.addWidget(self.lab_chi_cond, r, 1)

        # Log box
        r += 1
        self.log_box = QtWidgets.QPlainTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMaximumBlockCount(500)
        metrics.addWidget(self.log_box, r, 0, 1, 10)

        for c in range(10):
            metrics.setColumnStretch(c, 1)

        self._log("Tip: Close Arduino Serial Monitor. Select the ESP32 COM port, then Connect.")

    def _apply_dark_green_theme(self):
        self.setStyleSheet("""
            QMainWindow { background: #050607; color: #b6ffd5; }
            QWidget { background: #050607; color: #b6ffd5; }
            QPushButton { background: #0b1310; border: 1px solid #1cff88; padding: 6px; }
            QPushButton:hover { background: #0f1f18; }
            QComboBox { background: #0b1310; border: 1px solid #1cff88; padding: 4px; }
            QLabel { color: #b6ffd5; }
            QPlainTextEdit { background: #030404; border: 1px solid #1cff88; color: #b6ffd5; }
        """)
        pg.setConfigOption("background", (5, 6, 7))
        pg.setConfigOption("foreground", (182, 255, 213))

    def _log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        self.log_box.appendPlainText(f"[{ts}] {msg}")

    def refresh_ports(self):
        self.port_box.clear()
        ports = self.reader.ports()
        for p in ports:
            self.port_box.addItem(f"{p.device}  ({p.description})", p.device)
        if self.port_box.count() == 0:
            self.port_box.addItem("No ports found", "")

    def do_connect(self):
        port = self.port_box.currentData()
        if not port:
            return
        baud = int(self.baud_box.currentText())
        try:
            self.reader.connect(port, baud)
            self.status.setText("CONNECTED")
        except Exception as e:
            self.status.setText(f"CONNECT ERROR: {e}")
            self._log(f"Connect error: {e}")

    def do_disconnect(self):
        self.reader.close()
        self.status.setText("DISCONNECTED")
        self._log("Disconnected.")

    def _update_rx(self):
        if not self.reader.ser:
            self.lab_rx.setText("RX: 0 B/s")
            self.lab_pkts.setText("PKTS: ok=0 badcrc=0 badver=0 short=0 magic=0")
            return

        dt = self._rx_last_t.elapsed() / 1000.0
        if dt <= 0:
            return
        d = self.reader.rx_total - self._rx_last
        self._rx_last = self.reader.rx_total
        self._rx_last_t.restart()

        self.lab_rx.setText(f"RX: {int(d/dt)} B/s")
        self.lab_pkts.setText(
            f"PKTS: ok={self.reader.pkts_ok} badcrc={self.reader.pkts_bad_crc} badver={self.reader.pkts_bad_ver} "
            f"short={self.reader.pkts_short} magic={self.reader.magic_hits}"
        )

    def on_packet(self, p: dict):
        # ADC trace
        for v in p["adc"]:
            self.adc_trace.append(int(v))
        if len(self.adc_trace) > 10:
            y = np.array(self.adc_trace, dtype=np.int32)
            x = np.arange(len(y))
            self.adc_curve.setData(x, y)

        # byte windows
        self.vn_win.extend(p["vn"])
        self.cond_win.extend(p["cond"])
        vn_bytes = bytes(self.vn_win)
        cond_bytes = bytes(self.cond_win)

        # Update histograms
        if vn_bytes:
            counts = np.bincount(np.frombuffer(vn_bytes, dtype=np.uint8), minlength=256)
            self.bar_vn.setOpts(height=counts)
        if cond_bytes:
            counts2 = np.bincount(np.frombuffer(cond_bytes, dtype=np.uint8), minlength=256)
            self.bar_cond.setOpts(height=counts2)

        # Telemetry labels
        self.lab_ver.setText(f"0x{p['ver']:02X}")
        self.lab_seq.setText(str(p["seq"]))
        self.lab_wifi.setText(f"{p['wifi_scan_ms']} ms / {p['wifi_nets']} nets / {p['wifi_rssi']} dBm")
        self.lab_adc.setText(f"{p['adc_min']}/{p['adc_max']}/{p['adc_mean']}  sat:{p['adc_sat_low']}|{p['adc_sat_high']}")
        self.lab_vn.setText(str(p["vn_permille"]))

        if p.get("pickup_energy") is not None:
            self.lab_extra.setText(f"{p['pickup_energy']} / {p['jitter_span']} / {p['trng_mix']}")
        else:
            self.lab_extra.setText("(v0.1 packet: extras not present)")

        # Metrics
        H_vn = shannon_entropy_bytes(vn_bytes)
        H_cond = shannon_entropy_bytes(cond_bytes)
        Hmin_vn = min_entropy_bytes(vn_bytes)
        Hmin_cond = min_entropy_bytes(cond_bytes)

        self.lab_H_vn.setText(f"{H_vn:.3f}")
        self.lab_H_cond.setText(f"{H_cond:.3f}")
        self.lab_Hmin_vn.setText(f"{Hmin_vn:.3f}")
        self.lab_Hmin_cond.setText(f"{Hmin_cond:.3f}")

        # NIST-ish demo tests
        self.lab_freq_vn.setText(f"freq={freq_monobit(vn_bytes):.3f}")
        self.lab_runs_vn.setText(f"runs|z|={runs_test(vn_bytes):.2f}")
        self.lab_corr_vn.setText(f"corr={serial_correlation(vn_bytes):.3f}")
        self.lab_chi_vn.setText(f"chi={chi_square_256(vn_bytes):.1f}")

        self.lab_freq_cond.setText(f"freq={freq_monobit(cond_bytes):.3f}")
        self.lab_runs_cond.setText(f"runs|z|={runs_test(cond_bytes):.2f}")
        self.lab_corr_cond.setText(f"corr={serial_correlation(cond_bytes):.3f}")
        self.lab_chi_cond.setText(f"chi={chi_square_256(cond_bytes):.1f}")


def main():
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
