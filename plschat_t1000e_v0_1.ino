/* ============================================================================
 *  PLSChat T1000-E companion firmware  —  v0.1  (public-channel vertical slice)
 *  Target : Seeed SenseCAP T1000-E  (Nordic nRF52840 + Semtech LR1110)
 *  Role   : phone <--BLE(Nordic UART)--> T1000-E <--LoRa--> PLSChat mesh
 *
 *  This is the "confirmed-working base" for the new platform. It does ONE thing
 *  end to end: send and receive PUBLIC-channel PLSChat messages, byte-compatible
 *  with the Heltec v2.42 firmware, and bridge them to a phone over BLE.
 *  Private messages, contacts and rooms are deliberately NOT here yet — they
 *  need the Curve25519 + contact-store port and are the next milestone.
 *
 *  The PLSChat Android app (app-android/, BleActivity) is the phone-side half of
 *  this bridge: it speaks the exact NUS line protocol below.
 *
 *  ---------------------------------------------------------------------------
 *  BUILD
 *    Board core : Adafruit nRF52 core (Tools > Board > "Adafruit nRF52 Boards")
 *                 Pick a generic nRF52840 target. The pin numbers below are nRF
 *                 ABSOLUTE GPIO (P0.x = x, P1.x = 32 + x), taken verbatim from
 *                 Meshtastic variants/nrf52840/tracker-t1000-e/variant.h. Your
 *                 selected board must pass these through unmapped — if range is
 *                 dead, that mapping is the first thing to check (see FLAG 3).
 *    Libraries  : RadioLib            (Library Manager)  >= 6.x  (has LR1110)
 *                 Crypto              (rweather)         SHA256 / AES256 / CBC
 *    Flashing   : DFU over the four pogo pins — you need Seeed's pogo adapter.
 *
 *  ---------------------------------------------------------------------------
 *  NUS LINE PROTOCOL (matches app-android/BleActivity.java)
 *    app -> device :  "TX:<message>"   send a public-channel message
 *                     "WHO"            ask for this node's id
 *    device -> app :  "MSG:<8hexId>:<text>"   an incoming public message
 *                     "ME:<8hexId>"           reply to WHO (our node id)
 *
 *  ---------------------------------------------------------------------------
 *  THREE THINGS TO CONFIRM ON HARDWARE (everything else is verified):
 *    FLAG 1  RF-switch table for the LR1110 (see initRadio). Wrong table = the
 *            radio "works" on serial but transmits/receives almost nothing.
 *            Cross-check against Meshtastic's LR11x0 setup for this board.
 *    FLAG 2  Sync word. PLSChat uses 0x12. RadioLib should encode 0x12 the same
 *            on SX126x and LR11x0, but confirm a Heltec actually RX's a packet.
 *    FLAG 3  Pin passthrough (see BUILD note above).
 * ========================================================================== */

#include <RadioLib.h>
#include <bluefruit.h>
#include <SHA256.h>
#include <AES.h>
#include <CBC.h>
#include <nrf_soc.h>

// ---------------------------------------------------------------------------
//  Pin map  — Meshtastic variants/nrf52840/tracker-t1000-e/variant.h
//  nRF absolute GPIO: P0.x = x, P1.x = 32 + x
// ---------------------------------------------------------------------------
#define PIN_LORA_SCK   11    // P0.11
#define PIN_LORA_MISO  40    // P1.08
#define PIN_LORA_MOSI  41    // P1.09
#define PIN_LORA_NSS   12    // P0.12  (CS)
#define PIN_LORA_RST   42    // P1.10
#define PIN_LORA_IRQ   33    // P1.01  (DIO1 -> IRQ)
#define PIN_LORA_BUSY   7    // P0.07  (DIO2 wired as BUSY)
#define TCXO_VOLTAGE   1.6   // LR11x0 DIO3 drives the TCXO at 1.6 V

// ---------------------------------------------------------------------------
//  LoRa parameters  — MUST match the Heltec PLSChat build exactly
// ---------------------------------------------------------------------------
#define LORA_FREQ      868.0
#define LORA_BW        125.0
#define LORA_SF        10
#define LORA_CR        5
#define LORA_SYNC      0x12
#define LORA_POWER     22
#define LORA_PREAMBLE  16

// ---------------------------------------------------------------------------
//  PLSChat protocol constants (lifted from v2.42)
// ---------------------------------------------------------------------------
#define PKT_TYPE_MSG_PUB  0x01
#define PKT_TYPE_HELLO    0x03
#define MAX_MSG_LEN       64
#define AES_KEY_SIZE      32
#define AES_IV_SIZE       16
#define PKT_PUB_LEN       95          // 15 header + 16 IV + 64 ciphertext
static const char* PUBLIC_PASSPHRASE = "PLSChat-Public-Channel-2024";

// ---------------------------------------------------------------------------
//  Globals
// ---------------------------------------------------------------------------
LR1110  radio = new Module(PIN_LORA_NSS, PIN_LORA_IRQ, PIN_LORA_RST, PIN_LORA_BUSY);
BLEUart bleuart;                       // Nordic UART Service (NUS)

uint8_t  publicChannelKey[AES_KEY_SIZE];
uint32_t myNodeId = 0;
bool     radioReady = false;
volatile bool rxFlag = false;

#define SEEN_CACHE 24
uint32_t seenCache[SEEN_CACHE];
int      seenIdx = 0;

unsigned long lastHello = 0;
#define HELLO_INTERVAL_MS 60000UL      // 60s during bring-up; raise later for battery

String bleLine;                        // accumulates one command line from the phone
String serLine;                        // same, from USB serial (for headless testing)

// ---------------------------------------------------------------------------
//  Entropy — SoftDevice TRNG (valid only after Bluefruit.begin())
// ---------------------------------------------------------------------------
void randBytes(uint8_t* buf, uint8_t n) {
  uint8_t got = 0;
  while (got < n) {
    uint8_t avail = 0;
    sd_rand_application_bytes_available_get(&avail);
    if (avail == 0) { delay(1); continue; }
    uint8_t take = (uint8_t)min((int)(n - got), (int)avail);
    sd_rand_application_vector_get(buf + got, take);
    got += take;
  }
}

// ---------------------------------------------------------------------------
//  Crypto — must produce byte-identical results to the Heltec's mbedTLS path
// ---------------------------------------------------------------------------
void derivePublicKey() {
  SHA256 sha;
  sha.reset();
  sha.update((const uint8_t*)PUBLIC_PASSPHRASE, strlen(PUBLIC_PASSPHRASE));
  sha.finalize(publicChannelKey, AES_KEY_SIZE);          // = SHA-256(passphrase)
}

bool encryptCBC(const uint8_t* iv, const uint8_t* pt, size_t len, uint8_t* ct) {
  CBC<AES256> cbc;
  if (!cbc.setKey(publicChannelKey, AES_KEY_SIZE)) return false;
  cbc.setIV(iv, AES_IV_SIZE);
  cbc.encrypt(ct, pt, len);                               // len must be a multiple of 16
  return true;
}

bool decryptCBC(const uint8_t* iv, const uint8_t* ct, size_t len, uint8_t* pt) {
  CBC<AES256> cbc;
  if (!cbc.setKey(publicChannelKey, AES_KEY_SIZE)) return false;
  cbc.setIV(iv, AES_IV_SIZE);
  cbc.decrypt(pt, ct, len);
  return true;
}

// ---------------------------------------------------------------------------
//  Dedup — identical FNV-1a to the Heltec's packetHash()
// ---------------------------------------------------------------------------
uint32_t fnv1a(const uint8_t* buf, int len) {
  uint32_t h = 2166136261UL;
  for (int i = 0; i < len; i++) { h ^= buf[i]; h *= 16777619UL; }
  return h;
}
bool seenBefore(uint32_t id) {
  for (int i = 0; i < SEEN_CACHE; i++) if (seenCache[i] == id) return true;
  return false;
}
void markSeen(uint32_t id) {
  seenCache[seenIdx] = id;
  seenIdx = (seenIdx + 1) % SEEN_CACHE;
}

// ---------------------------------------------------------------------------
//  BLE out
// ---------------------------------------------------------------------------
void notifyPhone(const String& s) {
  if (Bluefruit.connected() && bleuart.notifyEnabled()) {
    bleuart.write((const uint8_t*)s.c_str(), s.length());
  }
}

// ---------------------------------------------------------------------------
//  TX — public message, byte-for-byte the v2.42 layout
//    [0]      type 0x01
//    [1..4]   srcNodeId (big-endian)
//    [5..8]   0xFF 0xFF 0xFF 0xFF (broadcast dst)
//    [9..12]  packet id (random)
//    [13]     hop/TTL = 3
//    [14]     ciphertext length = 64
//    [15..30] IV (16)
//    [31..94] ciphertext (64)
// ---------------------------------------------------------------------------
void sendPublic(const String& text) {
  if (!radioReady) return;

  uint8_t iv[AES_IV_SIZE]; randBytes(iv, AES_IV_SIZE);
  uint8_t pt[MAX_MSG_LEN]; memset(pt, 0, MAX_MSG_LEN);
  int t = min((int)text.length(), MAX_MSG_LEN - 1);
  memcpy(pt, text.c_str(), t);

  uint8_t ct[MAX_MSG_LEN];
  if (!encryptCBC(iv, pt, MAX_MSG_LEN, ct)) return;

  uint8_t pkt[PKT_PUB_LEN]; int i = 0;
  pkt[i++] = PKT_TYPE_MSG_PUB;
  pkt[i++] = (myNodeId >> 24) & 0xFF; pkt[i++] = (myNodeId >> 16) & 0xFF;
  pkt[i++] = (myNodeId >>  8) & 0xFF; pkt[i++] =  myNodeId        & 0xFF;
  pkt[i++] = 0xFF; pkt[i++] = 0xFF; pkt[i++] = 0xFF; pkt[i++] = 0xFF;
  uint32_t pid; randBytes((uint8_t*)&pid, 4);
  pkt[i++] = (pid >> 24) & 0xFF; pkt[i++] = (pid >> 16) & 0xFF;
  pkt[i++] = (pid >>  8) & 0xFF; pkt[i++] =  pid        & 0xFF;
  pkt[i++] = 3;                 // hops
  pkt[i++] = MAX_MSG_LEN;       // clen
  memcpy(&pkt[i], iv, AES_IV_SIZE); i += AES_IV_SIZE;
  memcpy(&pkt[i], ct, MAX_MSG_LEN); i += MAX_MSG_LEN;

  int st = radio.transmit(pkt, i);     // blocking TX is fine for this MVP
  radio.startReceive();
  Serial.printf("[TX] pub \"%s\" (radio %d)\n", text.c_str(), st);
}

// ---------------------------------------------------------------------------
//  TX — HELLO beacon. Lets a Heltec list this card as a seen node (good
//  connectivity check). Public key field left zero; the mesh only uses it
//  for contacts, which this build doesn't do yet.
// ---------------------------------------------------------------------------
void sendHello() {
  if (!radioReady) return;
  uint8_t pkt[42]; memset(pkt, 0, sizeof(pkt));
  pkt[0] = PKT_TYPE_HELLO;
  pkt[1] = (myNodeId >> 24) & 0xFF; pkt[2] = (myNodeId >> 16) & 0xFF;
  pkt[3] = (myNodeId >>  8) & 0xFF; pkt[4] =  myNodeId        & 0xFF;
  pkt[5] = 3;                        // hops
  radio.transmit(pkt, sizeof(pkt));
  radio.startReceive();
  lastHello = millis();
}

// ---------------------------------------------------------------------------
//  RX
// ---------------------------------------------------------------------------
void IRAM_ATTR onDio1() { rxFlag = true; }   // RADIOLIB calls this on packet RX

void handlePublic(uint8_t* buf, int len) {
  uint32_t src = ((uint32_t)buf[1] << 24) | ((uint32_t)buf[2] << 16) |
                 ((uint32_t)buf[3] <<  8) |  (uint32_t)buf[4];
  if (src == myNodeId) return;               // our own message, relayed back

  uint8_t cl = buf[14];
  if (cl == 0 || cl > MAX_MSG_LEN) return;
  if (len < 15 + AES_IV_SIZE + cl) return;

  uint8_t* iv = &buf[15];
  uint8_t* ct = &buf[15 + AES_IV_SIZE];
  uint8_t  pt[MAX_MSG_LEN + 1];
  if (!decryptCBC(iv, ct, cl, pt)) return;

  int actual = 0;                            // strip the zero padding
  for (int k = 0; k < cl; k++) if (pt[k] != 0) actual = k + 1;
  pt[actual] = '\0';

  char line[96];
  snprintf(line, sizeof(line), "MSG:%08X:%s\n", src, (char*)pt);
  notifyPhone(line);
  Serial.print(line);
}

void pollRadio() {
  if (!rxFlag) return;
  rxFlag = false;

  uint8_t buf[256];
  int len = radio.getPacketLength();
  int st  = radio.readData(buf, len);
  radio.startReceive();
  if (st != RADIOLIB_ERR_NONE || len < 2) return;

  uint32_t h = fnv1a(buf, len);
  if (seenBefore(h)) return;                 // duplicate flood copy
  markSeen(h);

  if (buf[0] == PKT_TYPE_MSG_PUB) handlePublic(buf, len);
  // HELLO / private / room types are ignored in this slice.
}

// ---------------------------------------------------------------------------
//  Command parsing (same grammar on BLE and USB serial)
//    TX:<text>   send a public message
//    WHO         report node id
// ---------------------------------------------------------------------------
void handleCommand(const String& cmdIn) {
  String cmd = cmdIn; cmd.trim();
  if (cmd.length() == 0) return;

  if (cmd.startsWith("TX:")) {
    sendPublic(cmd.substring(3));
  } else if (cmd == "WHO" || cmd == "who") {
    char line[32]; snprintf(line, sizeof(line), "ME:%08X\n", myNodeId);
    notifyPhone(line); Serial.print(line);
  }
}

void pumpStream(Stream& s, String& acc, bool fromBle) {
  while (s.available()) {
    char c = (char)s.read();
    if (c == '\n' || c == '\r') {
      if (acc.length()) { handleCommand(acc); acc = ""; }
    } else if (acc.length() < 200) {
      acc += c;
    }
  }
}
void pumpBle() {                              // BLEUart isn't a Stream subclass here
  while (bleuart.available()) {
    char c = (char)bleuart.read();
    if (c == '\n' || c == '\r') {
      if (bleLine.length()) { handleCommand(bleLine); bleLine = ""; }
    } else if (bleLine.length() < 200) {
      bleLine += c;
    }
  }
}

// ---------------------------------------------------------------------------
//  Setup
// ---------------------------------------------------------------------------
void initRadio() {
  SPI.setPins(PIN_LORA_MISO, PIN_LORA_SCK, PIN_LORA_MOSI);
  SPI.begin();

  int st = radio.begin(LORA_FREQ, LORA_BW, LORA_SF, LORA_CR,
                       LORA_SYNC, LORA_POWER, LORA_PREAMBLE, TCXO_VOLTAGE);
  if (st != RADIOLIB_ERR_NONE) {
    Serial.printf("[LoRa] begin FAILED: %d\n", st);
    radioReady = false;
    return;
  }

  /* FLAG 1 — RF SWITCH ----------------------------------------------------
   * The T1000-E routes TX/RX through an antenna switch driven by the LR1110's
   * own DIO lines (variant.h: LR11X0_DIO_AS_RF_SWITCH). RadioLib needs the
   * matching table or the part will appear to work yet barely radiate.
   * The pattern below is the RadioLib LR11x0 default; CONFIRM the DIO->mode
   * mapping against Meshtastic's LR11x0 setup for this board before trusting
   * range. If you only ever see your own loopback and nothing from a Heltec,
   * this is almost certainly why.
   *
   *   static const uint32_t rfswitch_pins[] =
   *     { RADIOLIB_LR11X0_DIO5, RADIOLIB_LR11X0_DIO6, RADIOLIB_NC,
   *       RADIOLIB_NC, RADIOLIB_NC };
   *   static const Module::RfSwitchMode_t rfswitch_table[] = {
   *     { LR11x0::MODE_STBY, { LOW,  LOW  } },
   *     { LR11x0::MODE_RX,   { HIGH, LOW  } },
   *     { LR11x0::MODE_TX,   { LOW,  HIGH } },
   *     { LR11x0::MODE_TX_HP,{ LOW,  HIGH } },
   *     END_OF_MODE_TABLE,
   *   };
   *   radio.setRfSwitchTable(rfswitch_pins, rfswitch_table);
   * -------------------------------------------------------------------- */

  radio.setDio1Action(onDio1);
  radio.startReceive();
  radioReady = true;
  Serial.println("[LoRa] ready");
}

void setup() {
  Serial.begin(115200);
  delay(300);

  myNodeId = NRF_FICR->DEVICEID[1];
  if (myNodeId == 0) myNodeId = NRF_FICR->DEVICEID[0];

  derivePublicKey();

  // BLE first so the SoftDevice TRNG is live before any encryption runs.
  Bluefruit.begin();
  Bluefruit.setName("PLSChat-T1000");
  Bluefruit.setTxPower(4);
  bleuart.begin();

  Bluefruit.Advertising.addFlags(BLE_GAP_ADV_FLAGS_LE_ONLY_GENERAL_DISC_MODE);
  Bluefruit.Advertising.addTxPower();
  Bluefruit.Advertising.addService(bleuart);
  Bluefruit.ScanResponse.addName();
  Bluefruit.Advertising.restartOnDisconnect(true);
  Bluefruit.Advertising.setInterval(32, 244);
  Bluefruit.Advertising.setFastTimeout(30);
  Bluefruit.Advertising.start(0);

  initRadio();

  Serial.printf("\nPLSChat T1000-E v0.1  node %08X\n", myNodeId);
  Serial.println("Serial cmds:  TX:<msg>   WHO");
}

void loop() {
  pollRadio();
  pumpBle();
  pumpStream(Serial, serLine, false);
  if (radioReady && millis() - lastHello >= HELLO_INTERVAL_MS) sendHello();
  delay(5);
}
