// ChaosField.ino - Chaos Field v0.3 (ESP32-WROOM-32 / NodeMCU 38-pin / USB-C)
//
// GOAL: Measurement + showcase entropy harvester for your pickup experiment.
// Not a crypto RNG product.
//
// SOURCES:
//  - Pickup ADC (GPIO34 / ADC1) ✅ works with Wi-Fi on
//  - esp_random() TRNG          ✅
//  - timing jitter (micros deltas + branch jitter) ✅
//  - Wi-Fi scan timing + RSSI + net count ✅
//
// ON-DEVICE:
//  - Von Neumann debias ✅
//  - SHA-256 conditioning/expansion ✅
//  - health + contribution meters ✅
//
// WIRING (screw terminals):
//  Pickup HOT -> P34 (GPIO34)
//  Pickup GND -> GND
//
// SERIAL FRAMING (binary):
//  [MAGIC 2] [VER 1] [SEQ u32] [FLAGS u16]
//  [TELEM fixed] [LEN adc u16] [LEN vn u16] [LEN cond u16]
//  [ADC payload u16 LE * N] [VN bytes] [COND bytes]
//  [CRC16-CCITT u16 LE]  (CRC over everything before CRC)
//
// NOTE:
//  - The PC GUI must have *exclusive* access to the COM port.
//    Close Arduino Serial Monitor/Plotter before using the GUI.
//
// ------------------------------------------------------------

#include <Arduino.h>
#include <WiFi.h>
#include "esp_system.h"
#include "esp_timer.h"
#include "mbedtls/sha256.h"

// -------------------- Build options --------------------
#define CHAOS_BAUD 921600     // If your USB-UART hates this, try 230400 or 115200.
#define CHAOS_HZ   5          // packets/sec

// -------------------- Pins -----------------------------
static const int PICKUP_PIN = 34; // ADC1 pin (input-only, safe with Wi-Fi)
static const int ADC_SAMPLES_PER_PACKET = 128;
static const int VN_BYTES_PER_PACKET    = 64;
static const int COND_BYTES_PER_PACKET  = 64;

// -------------------- Packet constants -----------------
static const uint8_t MAGIC0 = 0xCF;
static const uint8_t MAGIC1 = 0x42;
static const uint8_t VERSION = 0x03;

enum : uint16_t {
  F_WIFI_ON   = 1 << 0,
  F_WIFI_SCAN = 1 << 1,
  F_ADC_OK    = 1 << 2
};

// -------------------- Types ----------------------------
struct VNState {
  uint32_t raw_pairs = 0;
  uint32_t accepted = 0;
  bool have_prev = false;
  uint8_t prev = 0;
};

struct Telemetry {
  // ADC health
  uint16_t adc_min = 0;
  uint16_t adc_max = 0;
  uint16_t adc_mean = 0;
  uint16_t adc_sat_low = 0;
  uint16_t adc_sat_high = 0;

  // VN stats
  uint16_t vn_accept_permille = 0;

  // Wi-Fi scan stats
  uint16_t wifi_scan_ms = 0;
  uint16_t wifi_nets = 0;
  int16_t  wifi_rssi = 0;

  // “Contribution meters” (visualization only)
  uint16_t pickup_energy = 0; // sum abs deltas
  uint16_t jitter_span = 0;   // max dt - min dt in us sample window
  uint16_t trng_mix = 0;      // XOR fold of esp_random words

  // Timing
  uint16_t loop_us = 0;

  uint16_t flags = 0;
};

// -------------------- Globals ---------------------------
static uint16_t adc_buf[ADC_SAMPLES_PER_PACKET];

static bool wifi_scan_inflight = false;
static uint32_t wifi_scan_start_us = 0;
static uint16_t wifi_last_scan_ms = 0;
static uint16_t wifi_last_nets = 0;
static int16_t  wifi_last_rssi = 0;

static uint32_t seqno = 0;
static uint32_t next_send_us = 0;

// -------------------- Utility --------------------------
static inline uint32_t now_us() { return (uint32_t)esp_timer_get_time(); }

static uint16_t crc16_ccitt_update(uint16_t crc, uint8_t b) {
  crc ^= (uint16_t)b << 8;
  for (int i = 0; i < 8; i++) {
    crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
  }
  return crc;
}

static uint16_t crc16_ccitt(const uint8_t* data, size_t len) {
  uint16_t crc = 0xFFFF;
  for (size_t i = 0; i < len; i++) crc = crc16_ccitt_update(crc, data[i]);
  return crc;
}

static void sha256_32(const uint8_t* in, size_t in_len, uint8_t out32[32]) {
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  mbedtls_sha256_update(&ctx, in, in_len);
  mbedtls_sha256_finish(&ctx, out32);
  mbedtls_sha256_free(&ctx);
}

static void w_u16(uint8_t* b, size_t &o, uint16_t v) { b[o++] = v & 0xFF; b[o++] = v >> 8; }
static void w_s16(uint8_t* b, size_t &o, int16_t v)  { w_u16(b, o, (uint16_t)v); }
static void w_u32(uint8_t* b, size_t &o, uint32_t v) {
  b[o++] = (uint8_t)(v);
  b[o++] = (uint8_t)(v >> 8);
  b[o++] = (uint8_t)(v >> 16);
  b[o++] = (uint8_t)(v >> 24);
}

// -------------------- Wi-Fi scan -----------------------
static void start_wifi_scan_async() {
  wifi_scan_inflight = true;
  wifi_scan_start_us = now_us();
  WiFi.scanDelete();
  WiFi.scanNetworks(true /*async*/, true /*show_hidden*/);
}

static void poll_wifi_scan() {
  int res = WiFi.scanComplete();
  if (res == WIFI_SCAN_RUNNING) return;

  if (res >= 0) {
    wifi_last_nets = (uint16_t)res;
    wifi_last_scan_ms = (uint16_t)((now_us() - wifi_scan_start_us) / 1000);

    // strongest AP RSSI
    int best = -127;
    for (int i = 0; i < res; i++) {
      int r = (int)WiFi.RSSI(i);
      if (r > best) best = r;
    }
    wifi_last_rssi = (int16_t)best;

    WiFi.scanDelete();
  } else {
    wifi_last_nets = 0;
    wifi_last_scan_ms = 0;
    wifi_last_rssi = 0;
  }

  wifi_scan_inflight = false;
}

// -------------------- Von Neumann ----------------------
static bool vn_push_bit(VNState &st, uint8_t bit, uint8_t &out_bit) {
  bit &= 1;
  if (!st.have_prev) {
    st.prev = bit;
    st.have_prev = true;
    return false;
  }
  uint8_t a = st.prev;
  uint8_t b = bit;
  st.have_prev = false;
  st.raw_pairs++;

  if (a == b) return false;

  out_bit = (a == 1 && b == 0) ? 1 : 0; // 10->1, 01->0
  st.accepted++;
  return true;
}

// -------------------- Raw bit derivation ---------------
static uint8_t get_raw_bit(uint16_t adc_now, uint16_t adc_prev, uint32_t dt, uint32_t r) {
  uint32_t mix = 0;
  mix ^= (uint32_t)adc_now;
  mix ^= ((uint32_t)adc_prev << 12);
  mix ^= dt;
  mix ^= r;
  mix ^= ((uint32_t)wifi_last_scan_ms << 16);
  mix ^= ((uint32_t)(uint16_t)wifi_last_rssi << 8);
  mix ^= ((uint32_t)wifi_last_nets << 1);

  uint8_t b0 = (mix      ) & 1;
  uint8_t b1 = (mix >>  7) & 1;
  uint8_t b2 = (mix >> 15) & 1;
  return (b0 ^ b1 ^ b2) & 1;
}

// -------------------- Build VN bytes + telemetry --------
static void build_vn_bytes(uint8_t out_vn[VN_BYTES_PER_PACKET], Telemetry &tel) {
  VNState vn;

  uint32_t sum = 0;
  uint16_t mn = 0xFFFF, mx = 0;
  uint16_t sat_low = 0, sat_high = 0;

  // Capture ADC window
  for (int i = 0; i < ADC_SAMPLES_PER_PACKET; i++) {
    uint16_t v = (uint16_t)analogRead(PICKUP_PIN);
    adc_buf[i] = v;
    sum += v;
    mn = min(mn, v);
    mx = max(mx, v);
    if (v <= 8) sat_low++;
    if (v >= 4095 - 8) sat_high++;
    delayMicroseconds(60);
  }

  tel.adc_min = mn;
  tel.adc_max = mx;
  tel.adc_mean = (uint16_t)(sum / ADC_SAMPLES_PER_PACKET);
  tel.adc_sat_low = sat_low;
  tel.adc_sat_high = sat_high;

  // Contribution meter: pickup energy (sum abs deltas)
  uint32_t energy = 0;
  for (int i = 1; i < ADC_SAMPLES_PER_PACKET; i++) {
    int d = (int)adc_buf[i] - (int)adc_buf[i - 1];
    energy += (uint32_t)abs(d);
  }
  tel.pickup_energy = (uint16_t)min<uint32_t>(65535, energy);

  // Gather jitter span stats + TRNG fold
  uint32_t dt_min = 0xFFFFFFFF, dt_max = 0;
  uint32_t trng_fold = 0;

  // Produce VN bytes
  int out_idx = 0;
  uint8_t acc = 0;
  int bits = 0;

  uint16_t adc_prev = adc_buf[0];

  while (out_idx < VN_BYTES_PER_PACKET) {
    // jitter measurement
    uint32_t t0 = micros();
    uint32_t r  = esp_random();
    if (r & 1) asm volatile("nop\nnop\nnop\nnop\n");
    uint32_t t1 = micros();
    uint32_t dt = (t1 - t0);

    dt_min = min(dt_min, dt);
    dt_max = max(dt_max, dt);
    trng_fold ^= r;

    // rotate through ADC samples
    static int idx = 1;
    uint16_t adc_now = adc_buf[idx % ADC_SAMPLES_PER_PACKET];
    idx++;

    uint8_t raw = get_raw_bit(adc_now, adc_prev, dt, r);
    adc_prev = adc_now;

    uint8_t vnbit;
    if (vn_push_bit(vn, raw, vnbit)) {
      acc = (uint8_t)((acc << 1) | (vnbit & 1));
      bits++;
      if (bits == 8) {
        out_vn[out_idx++] = acc;
        bits = 0;
        acc = 0;
      }
    }
  }

  if (vn.raw_pairs > 0) {
    tel.vn_accept_permille = (uint16_t)((vn.accepted * 1000UL) / vn.raw_pairs);
  } else {
    tel.vn_accept_permille = 0;
  }

  tel.jitter_span = (uint16_t)min<uint32_t>(65535, (dt_max - dt_min));
  tel.trng_mix = (uint16_t)((trng_fold ^ (trng_fold >> 16)) & 0xFFFF);
}

// -------------------- Conditioning ----------------------
static void build_conditioned(const uint8_t vn[VN_BYTES_PER_PACKET],
                              const Telemetry &tel,
                              uint8_t out_cond[COND_BYTES_PER_PACKET]) {

  // Build blob: VN + telemetry + more TRNG
  uint8_t blob[VN_BYTES_PER_PACKET + 80];
  size_t o = 0;

  memcpy(blob + o, vn, VN_BYTES_PER_PACKET);
  o += VN_BYTES_PER_PACKET;

  auto put16 = [&](uint16_t v){ blob[o++] = v & 0xFF; blob[o++] = v >> 8; };
  auto puts16 = [&](int16_t v){ put16((uint16_t)v); };

  put16(tel.adc_min); put16(tel.adc_max); put16(tel.adc_mean);
  put16(tel.adc_sat_low); put16(tel.adc_sat_high);
  put16(tel.vn_accept_permille);
  put16(tel.wifi_scan_ms); put16(tel.wifi_nets); puts16(tel.wifi_rssi);
  put16(tel.pickup_energy); put16(tel.jitter_span); put16(tel.trng_mix);
  put16(tel.loop_us); put16(tel.flags);

  for (int i = 0; i < 8; i++) {
    uint32_t r = esp_random();
    blob[o++] = (uint8_t)r;
    blob[o++] = (uint8_t)(r >> 8);
    blob[o++] = (uint8_t)(r >> 16);
    blob[o++] = (uint8_t)(r >> 24);
  }

  // Expand to 64 bytes with SHA-256(blob || counter)
  uint8_t digest[32];
  for (int block = 0; block < 2; block++) {
    uint8_t tmp[sizeof(blob) + 1];
    memcpy(tmp, blob, sizeof(blob));
    tmp[sizeof(blob)] = (uint8_t)block;
    sha256_32(tmp, sizeof(tmp), digest);
    memcpy(out_cond + 32 * block, digest, 32);
  }
}

// -------------------- Packet send -----------------------
static void send_packet(const Telemetry &tel,
                        const uint8_t vn[VN_BYTES_PER_PACKET],
                        const uint8_t cond[COND_BYTES_PER_PACKET]) {

  const uint16_t adc_len  = ADC_SAMPLES_PER_PACKET * 2;
  const uint16_t vn_len   = VN_BYTES_PER_PACKET;
  const uint16_t cond_len = COND_BYTES_PER_PACKET;

  const size_t HEADER_MAX = 2 + 1 + 4 + 2 + (2 * 12) + 6;
  const size_t PACKET_MAX = HEADER_MAX + adc_len + vn_len + cond_len + 2;

  static uint8_t pkt[PACKET_MAX];
  size_t o = 0;

  pkt[o++] = MAGIC0;
  pkt[o++] = MAGIC1;
  pkt[o++] = VERSION;
  w_u32(pkt, o, seqno++);
  w_u16(pkt, o, tel.flags);

  // Telemetry packing (fixed order, GUI must match)
  w_u16(pkt, o, tel.adc_min);
  w_u16(pkt, o, tel.adc_max);
  w_u16(pkt, o, tel.adc_mean);
  w_u16(pkt, o, tel.adc_sat_low);
  w_u16(pkt, o, tel.adc_sat_high);

  w_u16(pkt, o, tel.vn_accept_permille);

  w_u16(pkt, o, tel.wifi_scan_ms);
  w_u16(pkt, o, tel.wifi_nets);
  w_s16(pkt, o, tel.wifi_rssi);

  w_u16(pkt, o, tel.pickup_energy);
  w_u16(pkt, o, tel.jitter_span);
  w_u16(pkt, o, tel.trng_mix);

  w_u16(pkt, o, tel.loop_us);

  // lengths
  w_u16(pkt, o, adc_len);
  w_u16(pkt, o, vn_len);
  w_u16(pkt, o, cond_len);

  // payloads
  for (int i = 0; i < ADC_SAMPLES_PER_PACKET; i++) {
    uint16_t v = adc_buf[i];
    pkt[o++] = (uint8_t)(v & 0xFF);
    pkt[o++] = (uint8_t)(v >> 8);
  }

  memcpy(pkt + o, vn, VN_BYTES_PER_PACKET);     o += VN_BYTES_PER_PACKET;
  memcpy(pkt + o, cond, COND_BYTES_PER_PACKET); o += COND_BYTES_PER_PACKET;

  // CRC
  uint16_t crc = crc16_ccitt(pkt, o);
  pkt[o++] = (uint8_t)(crc & 0xFF);
  pkt[o++] = (uint8_t)(crc >> 8);

  Serial.write(pkt, o);
  Serial.flush(); // helps some USB-UART bridges at high baud
}

// -------------------- Arduino setup/loop ----------------
void setup() {
  Serial.begin(CHAOS_BAUD);
  Serial.setTxBufferSize(4096);
  delay(250);

  analogReadResolution(12);
  analogSetPinAttenuation(PICKUP_PIN, ADC_11db);

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);

  start_wifi_scan_async();
  next_send_us = now_us();
}

void loop() {
  uint32_t t0 = now_us();

  poll_wifi_scan();

  Telemetry tel;
  tel.flags = F_WIFI_ON | F_ADC_OK;
  if (wifi_scan_inflight) tel.flags |= F_WIFI_SCAN;

  tel.wifi_scan_ms = wifi_last_scan_ms;
  tel.wifi_nets = wifi_last_nets;
  tel.wifi_rssi = wifi_last_rssi;

  uint8_t vn[VN_BYTES_PER_PACKET];
  uint8_t cond[COND_BYTES_PER_PACKET];

  build_vn_bytes(vn, tel);

  uint32_t t1 = now_us();
  tel.loop_us = (uint16_t)min<uint32_t>(65535, (t1 - t0));

  build_conditioned(vn, tel, cond);

  uint32_t now = now_us();
  uint32_t interval = 1000000UL / CHAOS_HZ;
  if ((int32_t)(now - next_send_us) >= 0) {
    send_packet(tel, vn, cond);
    next_send_us = now + interval;
  } else {
    delay(1);
  }
}
