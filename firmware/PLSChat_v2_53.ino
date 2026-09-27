#include <WiFi.h>
#include <esp_wifi.h>
#include <Preferences.h>
#include <U8g2lib.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLESecurity.h>
#include <WebServer.h>
#include <RadioLib.h>
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/bignum.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "esp_system.h"
#include "esp_efuse.h"
#include "PLSChatLicence.h"
// ====================== VERSION ======================
#define PLSCHAT_VERSION "v2.53"

// ====================== BOOT PIN CONFIG ======================
#define PIN_MIN_LENGTH    4
#define PIN_MAX_LENGTH    6
#define PIN_MAX_ATTEMPTS  3
#define PIN_LOCKOUT_MS    60000
#define PIN_WIPE_ATTEMPTS 3

// ====================== FORWARD DECLARATIONS ======================
void applyMode();
void loadLicence();
bool validateStoredLicence();
bool validateAndSaveLicence(String licenceStr);
void startWiFiAP();
void stopWiFiAP();
void startBLEServer();
void stopBLEServer();
void updateOLED();
void wakeOLED();
void sleepOLED();
void printStatus();
void drawScreenMain();
void drawScreenGraph();
void drawScreenDebug();
void drawScreenLora();
void drawScreenMessages();
void drawScreenPairing();
void setupWebServer();
void periodicSave();
void loadSavedState();
void saveMessages();
void loadMessages();
bool getChargingState();
float readVbatMv();
String getLifetimeString();
void enterSettingsMode();
void exitSettingsMode();
void tickUptime();
void updateRSSI();
void drawTick(int x, int y);
void drawCross(int x, int y);
void initLoRa();
void loopLoRa();
void sendHello();
void sendPublicMessage(String text);
void sendPrivateMessage(uint32_t destNodeId, String text);
void relayPacket(uint8_t* buf, int len);
bool seenBefore(uint32_t id);
void markSeen(uint32_t id);
uint32_t packetHash(uint8_t* buf, int len);
String loraSignalQuality();
ICACHE_RAM_ATTR void loraISR();
void initCrypto();
void generateKeyPair();
bool computeSharedSecretFromPubKey(uint8_t* theirPubKey, uint8_t* out);
bool getSharedKey(uint32_t nodeId, uint8_t* sharedKeyOut);
void storeSharedKey(uint32_t nodeId, uint8_t* sharedKey);
String getSafetyWords(uint32_t nodeId);
bool   isContactVerified(uint32_t nodeId);
void   setContactVerified(uint32_t nodeId, bool v);
bool encryptAES256(uint8_t* key, uint8_t* iv, uint8_t* plaintext, int len, uint8_t* ciphertext);
int  decryptAES256(uint8_t* key, uint8_t* iv, uint8_t* ciphertext, int len, uint8_t* plaintext);
void handleKeyExchange(uint8_t* buf, int len);
void sendKeyExchangePacket(uint32_t destNodeId, uint8_t pktType);
uint32_t getMyNodeId();
String generatePairingCode();
String getPairingPayload();
uint32_t parsePairingPayload(String payload, uint8_t* sharedKeyOut);
bool addContact(uint32_t nodeId, uint8_t* sharedKey, String name);
bool removeContact(uint32_t nodeId);
void saveContacts();
void loadContacts();
void saveRooms();
void loadRooms();
int  countRooms();
int  findRoom(uint32_t id);
bool getRoomKey(uint32_t id,uint8_t* out);
bool addRoom(uint32_t id,uint8_t* key,const char* name,bool priv=false,uint8_t maxM=50);
bool deleteRoom(uint32_t id);
void addRoomMember(uint32_t roomId,uint32_t nodeId);
String roomMembersStr(int ri);
void sendRoomMessage(uint32_t roomId,String text);
void sendRoomInvite(uint32_t destId,uint32_t roomId);
void handleRoomMessage(uint8_t* buf,int len);
void handleRoomInvite(uint8_t* buf,int len);
void sendAck(uint32_t destId,uint32_t pid,uint8_t type);
void handleAck(uint8_t* buf,int len,uint8_t type);
String getContactName(uint32_t nodeId);
bool isContact(uint32_t nodeId);
int  countContacts();
bool     bootPinEntry();
void     drawPinScreen(int dotsEntered, int attempt, bool wrong, bool locked);
void     hashPin(String pin, uint8_t* hashOut);
bool     checkPin(String pin);
bool     isPinSet();
void     setPin(String pin);
void     wipeDevice();
bool     isFirstBoot();
void     clearFirstBoot();
void     drawWipeWarning(int seconds);
void     drawChangePinScreen();
String   collectPinInput(String prompt, bool confirm);

// ====================== Pin Definitions ======================
#define OLED_SDA       17
#define OLED_SCL       18
#define OLED_RST       21
#define VBAT_PIN        1
#define ADC_CTRL_PIN   37
#define VEXT_PIN       36
#define BTN_PIN         0
#define WHITE_LED      35
#define SAVE_INTERVAL_MS  1800000UL
#define LONG_PRESS_MS      3000
#define SETTINGS_TIMEOUT  300000
#define DEFAULT_WIFI_SSID "PLSChat-Repeater"
#define DEFAULT_WIFI_PASS "pls12345"
#define DEFAULT_BLE_NAME  "PLSChat-Repeater"
#define DEFAULT_BLE_PIN   "1234"

// ====================== LoRa Pins ======================
#define LORA_SCK   9
#define LORA_MISO 11
#define LORA_MOSI 10
#define LORA_CS    8
#define LORA_RST  12
#define LORA_BUSY 13
#define LORA_DIO1 14

// ====================== LoRa Settings ======================
#define LORA_FREQUENCY  868.0
#define LORA_BANDWIDTH  125.0
#define LORA_SF          10
#define LORA_CR           5
#define LORA_SYNC_WORD  0x12
#define LORA_TX_POWER    22
#define LORA_PREAMBLE    16

// ====================== Packet Types ======================
#define PKT_TYPE_MSG_PUB   0x01
#define PKT_TYPE_ACK       0x02
#define PKT_TYPE_HELLO     0x03
#define PKT_TYPE_RELAY     0x04
#define PKT_TYPE_MSG_PRIV  0x05
#define PKT_TYPE_KEY_REQ   0x06
#define PKT_TYPE_KEY_ACK   0x07
#define PKT_TYPE_REVOKE    0x08
#define PKT_TYPE_PAIR_REQ  0x09
#define PKT_TYPE_PAIR_ACK  0x0A
#define PKT_TYPE_PAIR_REJ  0x0B
#define PKT_TYPE_ROOM_MSG    0x0C
#define PKT_TYPE_ROOM_INVITE 0x0D
#define PKT_TYPE_DELIVERED   0x0E
#define PKT_TYPE_READ        0x0F

// ====================== Crypto ======================
#define PUBLIC_CHANNEL_PASSPHRASE "PLSChat-Public-Channel-2024"
#define CURVE25519_KEY_SIZE 32
#define AES_KEY_SIZE        32
#define AES_IV_SIZE         16
#define AES_BLOCK_SIZE      16
#define MAX_PAIRED_NODES    10

// ====================== Pairing code ======================
#define PAIR_ALPHA    "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
#define PAIR_CODE_LEN 8

// ====================== Contact store ======================
#define MAX_CONTACTS     10
#define CONTACT_NAME_LEN 16

struct Contact {
  uint32_t      nodeId;
  uint8_t       sharedKey[AES_KEY_SIZE];
  char          name[CONTACT_NAME_LEN];
  bool          valid;
  bool          verified;    // out-of-band safety-word confirmation; auto-resets on key change
  unsigned long pairedAt;
};
Contact contacts[MAX_CONTACTS];

#define MAX_ROOMS 8
#define ROOM_NAME_LEN 20
#define MAX_ROOM_MEMBERS 12
struct Room {
  uint32_t      roomId;
  uint8_t       key[AES_KEY_SIZE];
  char          name[ROOM_NAME_LEN];
  uint32_t      members[MAX_ROOM_MEMBERS];
  uint8_t       memberCount;
  bool          valid;
  bool          isPrivate;   // invite key required to join
  uint8_t       maxMsgs;     // max stored messages (10-200)
};
Room rooms[MAX_ROOMS];

// ====================== Message store ======================
#define MAX_MESSAGES 40
#define MAX_MSG_LEN  64

struct ChatMessage {
  uint32_t      fromNode;
  bool          isPrivate;
  bool          isMe;
  uint32_t      toNode;
  uint32_t      roomId;
  uint32_t      msgId;
  uint8_t       status;
  char          text[MAX_MSG_LEN];
  unsigned long timestamp;
};
ChatMessage messageStore[MAX_MESSAGES];
int  messageCount  = 0;
int  messageHead   = 0;
bool newMessageFlag = false;
bool messagesDirty  = false;
unsigned long lastMsgSave = 0;

// ====================== Crypto globals ======================
uint8_t myPrivateKey[CURVE25519_KEY_SIZE];
uint8_t myPublicKey[CURVE25519_KEY_SIZE];
bool    cryptoReady = false;
uint8_t publicChannelKey[AES_KEY_SIZE];

mbedtls_entropy_context  entropy;
mbedtls_ctr_drbg_context ctrDrbg;

// ====================== Security state ======================
bool    deviceUnlocked     = false;
int     pinAttempts        = 0;
bool    pinLockedOut       = false;
unsigned long lockoutStart = 0;
bool    changingPin        = false;

String        sessionToken    = "";
unsigned long sessionExpiry   = 0;
unsigned long lastWebActivity = 0;
int           sessionMinutes  = 5;
#define SESSION_COOKIE "plsc_session"

struct PairRequest {
  uint32_t      nodeId    = 0;
  String        name      = "";
  bool          pending   = false;
  bool          accepted  = false;
  bool          rejected  = false;
  unsigned long sentAt    = 0;
} pairReq;

struct IncomingPairReq {
  uint32_t      fromNode   = 0;
  uint8_t       pubKey[32];
  bool          pending    = false;
  bool          accepted   = false;
  unsigned long receivedAt = 0;
  unsigned long acceptedAt = 0;
} incomingPair;
#define PAIR_REQUEST_TIMEOUT 60000

// ====================== OLED / Web ======================
U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2(U8G2_R0, OLED_RST, OLED_SCL, OLED_SDA);
WebServer server(80);

#define SERVICE_UUID        "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define CHARACTERISTIC_UUID "beb5483e-36e1-4688-b7f5-ea07361b26a8"

#define LOGO_W 16
#define LOGO_H 16
const unsigned char plschat_logo[] PROGMEM = {
  0x80,0x00,0xE0,0x03,0xFC,0x0F,0xFF,0x3F,
  0xDF,0x3F,0x5F,0x3F,0x4F,0x3E,0x21,0x01,
  0xBF,0x3F,0xBF,0x3F,0xBF,0x3F,0xFC,0x0F,
  0xF8,0x03,0xE0,0x01,0x40,0x00,0x00,0x00
};

Preferences prefs;
Preferences licencePrefs;
Preferences secPrefs;

bool          isLicensed     = false;
String        licenceKey     = "";
unsigned long licenceExpiry  = 0;
// --- Wall-clock estimate for "days left" display (device has no RTC/internet) ---
// The connector app (browser) sends TIME:<unix_epoch> over serial whenever it connects.
// We anchor that epoch to our persisted lifetimeSeconds counter so the estimate survives
// reboots. Between re-syncs, remaining days can only be OVER-estimated (if the device is
// powered off for long stretches), never under-estimated — safe direction for display.
uint32_t      timeSyncEpoch        = 0;   // real-world unix time at last sync
unsigned long timeSyncLifetimeSecs = 0;   // lifetimeSeconds value captured at that sync
bool          timeSynced           = false;

bool   wifiEnabled    = true;
bool   bleEnabled     = false;
bool   settingsMode   = false;
bool   prevModeWasBLE = false;
bool   showMsgOnOLED  = false;

String wifiSSID = DEFAULT_WIFI_SSID;
String wifiPass = DEFAULT_WIFI_PASS;
String bleName  = DEFAULT_BLE_NAME;
String blePin   = DEFAULT_BLE_PIN;

int  currentRSSI   = -99;
int  clientCount   = 0;
int  batPct        = 0;
bool isCharging    = false;
int  chargeFrame   = 0;
bool lowBatWarning     = false;
bool batWarningVisible = true;

// Battery configuration (saved in NVS, adjustable in Settings)
int   batCapMah  = 1000;     // mAh capacity — display/info only
float batMinMv   = 3000.0f;  // voltage at 0%
float batMaxMv   = 4180.0f;  // voltage at 100%
bool  batLiFePO4 = false;    // true = use LiFePO4 discharge curve
float batDivider = 4.9f;     // ADC divider/calibration multiplier (Heltec V3 = ~4.9; tune to a multimeter)

unsigned long uptimeSeconds    = 0;
unsigned long lifetimeSeconds  = 0;
unsigned long lastUptimeTick   = 0;
unsigned long lastRSSITime     = 0;
unsigned long lastStatusTime   = 0;
unsigned long lastBatTime      = 0;
unsigned long lastChargeAnim   = 0;
unsigned long lastBatFlash     = 0;
unsigned long lastSaveTime     = 0;
unsigned long settingsModeStart = 0;
unsigned long lastOledActivity  = 0;
bool          oledOn            = true;
#define OLED_TIMEOUT_MS 30000

int  currentSaveSlot = 0;

unsigned long btnPressTime   = 0;
bool          btnLongHandled = false;

#define RSSI_HISTORY 30
int  rssiHistory[RSSI_HISTORY];
int  rssiIndex       = 0;
bool rssiHistoryFull = false;
unsigned long lastRSSIHistory = 0;

#define SCREEN_MAIN     0
#define SCREEN_MESSAGES 1
#define SCREEN_PAIRING  2
#define SCREEN_GRAPH    3
#define SCREEN_DEBUG    4
#define SCREEN_LORA     5
#define NUM_SCREENS     6

volatile int  currentScreen = SCREEN_MAIN;
volatile bool btnPressed    = false;
volatile bool btnDown       = false;
unsigned long lastBtnTime   = 0;

BLEServer* pBLEServer = nullptr;
bool bleRunning = false;

// ====================== LoRa globals ======================
SX1262 radio = new Module(LORA_CS, LORA_DIO1, LORA_RST, LORA_BUSY);
bool          loraReady       = false;
volatile bool loraRxFlag      = false;
int           loraRSSI        = 0;
float         loraSNR         = 0.0;
float         loraFreqErr     = 0.0;
unsigned long packetsReceived = 0;
unsigned long packetsRelayed  = 0;
unsigned long lastLoraRx      = 0;
String        lastNodeSeen    = "";
unsigned long lastHello       = 0;

#define SEEN_CACHE_SIZE 20
uint32_t seenCache[SEEN_CACHE_SIZE];
int seenCacheIdx = 0;

// =============================================================
//  SECTION 1 — BOOT PIN SYSTEM
// =============================================================
void hashPin(String pin, uint8_t* hashOut) {
  String salted = "PLSChat_PIN_SALT_" + WiFi.macAddress() + "_" + pin;
  mbedtls_sha256_context sha;
  mbedtls_sha256_init(&sha);
  mbedtls_sha256_starts(&sha, 0);
  mbedtls_sha256_update(&sha,(const unsigned char*)salted.c_str(), salted.length());
  mbedtls_sha256_finish(&sha, hashOut);
  mbedtls_sha256_free(&sha);
}

bool isPinSet() {
  secPrefs.begin("security", true);
  bool set = secPrefs.getBytesLength("pinHash") == 32;
  secPrefs.end();
  return set;
}

void setPin(String pin) {
  uint8_t hash[32];
  hashPin(pin, hash);
  secPrefs.begin("security", false);
  secPrefs.putBytes("pinHash", hash, 32);
  secPrefs.putInt("pinAttempts", 0);
  secPrefs.end();
  Serial.println("[Security] PIN set");
}

bool checkPin(String pin) {
  uint8_t stored[32], entered[32];
  secPrefs.begin("security", true);
  size_t len = secPrefs.getBytes("pinHash", stored, 32);
  secPrefs.end();
  if (len != 32) return false;
  hashPin(pin, entered);
  uint8_t diff = 0;
  for (int i = 0; i < 32; i++) diff |= stored[i] ^ entered[i];
  return diff == 0;
}

bool isFirstBoot() {
  secPrefs.begin("security", true);
  bool fb = !secPrefs.getBool("booted", false);
  secPrefs.end();
  return fb;
}
void clearFirstBoot() {
  secPrefs.begin("security", false);
  secPrefs.putBool("booted", true);
  secPrefs.end();
}
String generateSessionToken(){
  if(!cryptoReady){return "DEVTOKEN12345678DEVTOKEN12345678";}
  uint8_t buf[16];
  mbedtls_ctr_drbg_random(&ctrDrbg,buf,sizeof(buf));
  String t="";
  for(int i=0;i<16;i++){char h[3];sprintf(h,"%02X",buf[i]);t+=h;}
  return t;
}
void startWebSession(){
  sessionToken=generateSessionToken();
  lastWebActivity=millis();
  sessionExpiry=(sessionMinutes>0)?millis()+(unsigned long)sessionMinutes*60000UL:0xFFFFFFFFUL;
  deviceUnlocked=true;
  Serial.printf("[Session] Started, %d min timeout\n",sessionMinutes);
}
bool isSessionValid(){
  if(!deviceUnlocked||sessionToken.length()==0)return false;
  if(sessionMinutes>0&&millis()>sessionExpiry){
    deviceUnlocked=false;sessionToken="";
    Serial.println("[Session] Expired");return false;
  }
  return true;
}
bool checkSessionCookie(){
  if(!isSessionValid())return false;
  String cookie=server.header("Cookie");
  return cookie.indexOf(String(SESSION_COOKIE)+"="+sessionToken)>=0;
}
void setSessionCookie(){
  server.sendHeader("Set-Cookie",String(SESSION_COOKIE)+"="+sessionToken+"; Path=/; HttpOnly; SameSite=Lax");
}
void touchSession(){
  lastWebActivity=millis();
  if(sessionMinutes>0)sessionExpiry=millis()+(unsigned long)sessionMinutes*60000UL;
}

void wipeDevice() {
  Serial.println("[Security] !!! WIPING DEVICE !!!");
  prefs.begin("plschat", false);
  prefs.remove("privKey");
  prefs.remove("pubKey");
  prefs.end();
  Preferences cp;
  cp.begin("contacts", false);
  cp.clear();
  cp.end();
  secPrefs.begin("security", false);
  secPrefs.clear();
  secPrefs.end();
  licencePrefs.begin("lic", false);
  licencePrefs.clear();
  licencePrefs.end();
  // Also wipe PLSChatLicence.h NVS namespace
  Preferences lp;
  lp.begin("plschat_lic", false);
  lp.clear();
  lp.end();
  memset(myPrivateKey, 0, sizeof(myPrivateKey));
  memset(myPublicKey,  0, sizeof(myPublicKey));
  for (int i = 0; i < MAX_CONTACTS; i++) {
    memset(contacts[i].sharedKey, 0, AES_KEY_SIZE);
    contacts[i].valid = false;
  }
  cryptoReady = false;
  Serial.println("[Security] Wipe complete. Rebooting...");
  delay(1000);
  esp_restart();
}

void drawPinScreen(int dots, int attempt, bool wrong, bool locked) {
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_7x13B_tr);
  if (locked) {
    u8g2.drawStr(10, 20, "LOCKED");
    u8g2.setFont(u8g2_font_5x7_tr);
    unsigned long remaining = (PIN_LOCKOUT_MS - (millis() - lockoutStart)) / 1000;
    char buf[32]; sprintf(buf, "Wait %lu seconds", remaining + 1);
    u8g2.drawStr(10, 35, buf);
    u8g2.drawStr(0, 50, "Too many wrong PINs");
    u8g2.sendBuffer();
    return;
  }
  u8g2.drawStr(20, 16, "Enter PIN");
  u8g2.drawHLine(0, 19, 128);
  int dotSpacing = 14;
  int dotStart   = (128 - (PIN_MAX_LENGTH * dotSpacing)) / 2;
  for (int i = 0; i < PIN_MAX_LENGTH; i++) {
    int x = dotStart + i * dotSpacing;
    if (i < dots) u8g2.drawDisc(x + 5, 35, 5);
    else          u8g2.drawCircle(x + 5, 35, 5);
  }
  u8g2.setFont(u8g2_font_5x7_tr);
  if (wrong) {
    char buf[32];
    int remaining = PIN_MAX_ATTEMPTS - attempt;
    if (remaining <= 2) {
      sprintf(buf, "WRONG! %d left", remaining);
      u8g2.drawStr(20, 52, buf);
      if (remaining == 1) u8g2.drawStr(5, 62, "Next fail = WIPE!");
    } else {
      u8g2.drawStr(30, 52, "Wrong PIN");
    }
  } else if (attempt > 0) {
    char buf[24]; sprintf(buf, "Attempt %d/%d", attempt + 1, PIN_MAX_ATTEMPTS);
    u8g2.drawStr(25, 52, buf);
  } else {
    u8g2.drawStr(5, 52, "Hold BTN = next digit");
    u8g2.drawStr(5, 62, "Short press = confirm");
  }
  u8g2.sendBuffer();
}

void drawWipeWarning(int seconds) {
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_7x13B_tr);
  u8g2.drawStr(5, 18, "!! WIPING !!");
  u8g2.setFont(u8g2_font_5x7_tr);
  u8g2.drawStr(0, 32, "Too many failed PINs");
  u8g2.drawStr(0, 44, "All data being erased");
  char buf[20]; sprintf(buf, "Wiping in %ds...", seconds);
  u8g2.drawStr(15, 58, buf);
  u8g2.sendBuffer();
}

void drawFirstBootPinScreen(int step, int dots, bool confirm, bool mismatch) {
  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_5x7_tr);
  if (step == 0) {
    u8g2.drawStr(0, 10, "FIRST BOOT SETUP");
    u8g2.drawHLine(0, 12, 128);
    u8g2.drawStr(0, 24, "Set your boot PIN");
    u8g2.drawStr(0, 34, "4-6 digits");
    u8g2.drawStr(0, 44, "Protects your keys");
    u8g2.drawStr(0, 54, "& contacts");
    u8g2.drawStr(0, 63, "Press BTN to start");
  } else {
    u8g2.drawStr(0, 10, confirm ? "Confirm PIN:" : "New PIN:");
    u8g2.drawHLine(0, 12, 128);
    int dotSpacing = 14;
    int dotStart   = (128 - (PIN_MAX_LENGTH * dotSpacing)) / 2;
    for (int i = 0; i < PIN_MAX_LENGTH; i++) {
      int x = dotStart + i * dotSpacing;
      if (i < dots) u8g2.drawDisc(x+5, 35, 5);
      else          u8g2.drawCircle(x+5, 35, 5);
    }
    if (mismatch) {
      u8g2.drawStr(15, 55, "PINs don't match!");
      u8g2.drawStr(20, 63, "Try again");
    } else {
      u8g2.drawStr(0, 55, "Hold=next  Short=ok");
    }
  }
  u8g2.sendBuffer();
}

String collectPinDigits(int maxLen) {
  String pin = "";
  int currentDigit = 0;
  while ((int)pin.length() < maxLen) {
    while (digitalRead(BTN_PIN) == HIGH) delay(20);
    unsigned long pressStart = millis();
    while (digitalRead(BTN_PIN) == LOW) delay(20);
    unsigned long pressDuration = millis() - pressStart;
    if (pressDuration > 600) {
      currentDigit = (currentDigit + 1) % 10;
      return "__DIGIT_" + String(currentDigit) + "__";
    } else {
      pin += String(currentDigit);
      currentDigit = 0;
      if ((int)pin.length() >= PIN_MIN_LENGTH) {
        unsigned long waitStart = millis();
        bool anotherPress = false;
        while (millis() - waitStart < 800) {
          if (digitalRead(BTN_PIN) == LOW) { anotherPress = true; break; }
          delay(20);
        }
        if (!anotherPress) continue;
        else {
          while (digitalRead(BTN_PIN) == LOW) delay(20);
          return pin;
        }
      }
    }
  }
  return pin;
}

bool bootPinEntry() {
  if (isFirstBoot() || !isPinSet()) {
    drawFirstBootPinScreen(0, 0, false, false);
    while (digitalRead(BTN_PIN) == HIGH) delay(50);
    while (digitalRead(BTN_PIN) == LOW)  delay(50);
    delay(200);
    String newPin = "", confirmPin = "";
    bool mismatch = false;
    while (true) {
      newPin = "";
      drawFirstBootPinScreen(1, 0, false, mismatch);
      for (int i = 0; i < PIN_MAX_LENGTH; i++) {
        int d = 0; bool committed = false;
        while (!committed) {
          drawFirstBootPinScreen(1, i, false, false);
          u8g2.setFont(u8g2_font_7x13B_tr);
          char dc[3]; sprintf(dc, "%d", d);
          u8g2.drawStr(110, 45, dc);
          u8g2.sendBuffer();
          while (digitalRead(BTN_PIN) == HIGH) delay(20);
          unsigned long ps = millis();
          while (digitalRead(BTN_PIN) == LOW)  delay(20);
          unsigned long dur = millis() - ps;
          if (dur > 600) { d = (d + 1) % 10; }
          else { newPin += String(d); d = 0; committed = true; }
        }
        if ((int)newPin.length() >= PIN_MIN_LENGTH) {
          drawFirstBootPinScreen(1, newPin.length(), false, false);
          u8g2.setFont(u8g2_font_5x7_tr);
          u8g2.drawStr(30, 63, "Press to submit");
          u8g2.sendBuffer();
          unsigned long ws = millis(); bool submit = false;
          while (millis() - ws < 1200) {
            if (digitalRead(BTN_PIN) == LOW) { submit = true; break; }
            delay(20);
          }
          if (submit) { while(digitalRead(BTN_PIN)==LOW) delay(20); break; }
        }
      }
      confirmPin = ""; mismatch = false;
      for (int i = 0; i < (int)newPin.length(); i++) {
        int d = 0; bool committed = false;
        while (!committed) {
          drawFirstBootPinScreen(1, i, true, false);
          u8g2.setFont(u8g2_font_7x13B_tr);
          char dc[3]; sprintf(dc, "%d", d);
          u8g2.drawStr(110, 45, dc);
          u8g2.sendBuffer();
          while (digitalRead(BTN_PIN) == HIGH) delay(20);
          unsigned long ps = millis();
          while (digitalRead(BTN_PIN) == LOW)  delay(20);
          unsigned long dur = millis() - ps;
          if (dur > 600) { d = (d + 1) % 10; }
          else { confirmPin += String(d); committed = true; }
        }
      }
      if (newPin == confirmPin && (int)newPin.length() >= PIN_MIN_LENGTH) {
        setPin(newPin); clearFirstBoot();
        u8g2.clearBuffer(); u8g2.setFont(u8g2_font_7x13B_tr);
        u8g2.drawStr(15, 25, "PIN SET!");
        u8g2.setFont(u8g2_font_5x7_tr);
        u8g2.drawStr(5, 42, "Remember your PIN.");
        u8g2.drawStr(5, 52, "Wrong PIN x10 wipes");
        u8g2.drawStr(5, 62, "all data.");
        u8g2.sendBuffer(); delay(3000);
        return true;
      } else {
        mismatch = true;
        drawFirstBootPinScreen(1, 0, false, true);
        u8g2.sendBuffer(); delay(1500);
      }
    }
  }
  int attempts = 0; bool wrong = false;
  while (attempts < PIN_WIPE_ATTEMPTS) {
    if (pinLockedOut) {
      if (millis() - lockoutStart < PIN_LOCKOUT_MS) { drawPinScreen(0, attempts, false, true); delay(500); continue; }
      else pinLockedOut = false;
    }
    drawPinScreen(0, attempts, wrong, false); wrong = false;
    String enteredPin = "";
    for (int i = 0; i < PIN_MAX_LENGTH; i++) {
      int d = 0; bool committed = false;
      while (!committed) {
        drawPinScreen(enteredPin.length(), attempts, false, false);
        u8g2.setFont(u8g2_font_7x13B_tr);
        char dc[3]; sprintf(dc, "%d", d);
        u8g2.drawStr(108, 50, dc);
        u8g2.sendBuffer();
        while (digitalRead(BTN_PIN) == HIGH) delay(20);
        unsigned long ps = millis();
        while (digitalRead(BTN_PIN) == LOW)  delay(20);
        unsigned long dur = millis() - ps;
        if (dur > 600) { d = (d + 1) % 10; }
        else { enteredPin += String(d); committed = true; }
      }
      if ((int)enteredPin.length() >= PIN_MIN_LENGTH) {
        drawPinScreen(enteredPin.length(), attempts, false, false);
        u8g2.setFont(u8g2_font_5x7_tr);
        u8g2.drawStr(25, 62, "Hold to submit");
        u8g2.sendBuffer();
        unsigned long ws = millis(); bool doSubmit = false;
        while (millis() - ws < 1500) {
          if (digitalRead(BTN_PIN) == LOW) {
            unsigned long hs = millis();
            while (digitalRead(BTN_PIN) == LOW) delay(20);
            if (millis() - hs > 600) { doSubmit = true; break; }
          }
          delay(20);
        }
        if (doSubmit) break;
      }
    }
    if (checkPin(enteredPin)) {
      pinAttempts = 0;
      secPrefs.begin("security", false); secPrefs.putInt("pinAttempts", 0); secPrefs.end();
      u8g2.clearBuffer(); u8g2.setFont(u8g2_font_7x13B_tr);
      u8g2.drawStr(20, 30, "Unlocked!"); drawTick(50, 38); u8g2.sendBuffer(); delay(800);
      return true;
    } else {
      attempts++; wrong = true;
      secPrefs.begin("security", false); secPrefs.putInt("pinAttempts", attempts); secPrefs.end();
      Serial.printf("[Security] Wrong PIN, attempt %d/%d\n", attempts, PIN_WIPE_ATTEMPTS);
      if (attempts >= PIN_MAX_ATTEMPTS && attempts < PIN_WIPE_ATTEMPTS) {
        pinLockedOut = true; lockoutStart = millis();
        unsigned long lockDuration = PIN_LOCKOUT_MS * (attempts - PIN_MAX_ATTEMPTS + 1);
        drawPinScreen(0, attempts, true, true); delay(lockDuration); pinLockedOut = false;
      }
      if (attempts >= PIN_WIPE_ATTEMPTS - 2) { for (int i = 3; i >= 1; i--) { drawWipeWarning(i); delay(1000); } }
      if (attempts >= PIN_WIPE_ATTEMPTS) { wipeDevice(); return false; }
    }
  }
  return false;
}

// =============================================================
//  SECTION 2 — NODE ID / PAIRING CODE
// =============================================================
uint32_t getMyNodeId() {
  String macStr = WiFi.macAddress();
  uint8_t mac[6];
  sscanf(macStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]);
  return ((uint32_t)mac[2]<<24)|((uint32_t)mac[3]<<16)|((uint32_t)mac[4]<<8)|(uint32_t)mac[5];
}
String generatePairingCode() {
  if (!cryptoReady) return "--------";
  const char* alpha = PAIR_ALPHA; int alen = strlen(alpha);
  uint32_t id = getMyNodeId();
  uint8_t seed[6];
  seed[0]=(id>>24)&0xFF; seed[1]=(id>>16)&0xFF; seed[2]=(id>>8)&0xFF; seed[3]=id&0xFF;
  seed[4]=myPublicKey[0]; seed[5]=myPublicKey[1];
  char code[PAIR_CODE_LEN+1];
  for (int i=0;i<PAIR_CODE_LEN;i++) code[i]=alpha[(seed[i%6]+i*7+myPublicKey[i%32])%alen];
  code[PAIR_CODE_LEN]='\0';
  return String(code);
}
String getPairingPayload() {
  if (!cryptoReady) return "";
  char buf[80]; char pkHex[65];
  for (int i=0;i<CURVE25519_KEY_SIZE;i++) sprintf(&pkHex[i*2],"%02X",myPublicKey[i]);
  pkHex[64]='\0';
  sprintf(buf,"PLSC:%08X:%s",getMyNodeId(),pkHex);
  return String(buf);
}
uint32_t parsePairingPayload(String payload, uint8_t* sharedKeyOut) {
  payload.trim();
  if (payload.startsWith("PLSC:")) payload=payload.substring(5);
  int colon=payload.indexOf(':');
  if (colon!=8) return 0;
  String nodeIdStr=payload.substring(0,8);
  String pubKeyStr=payload.substring(9);
  if (pubKeyStr.length()!=64) return 0;
  uint32_t nodeId=(uint32_t)strtoul(nodeIdStr.c_str(),nullptr,16);
  if (nodeId==0) return 0;
  uint8_t theirPubKey[CURVE25519_KEY_SIZE];
  for (int i=0;i<CURVE25519_KEY_SIZE;i++) {
    char b[3]={pubKeyStr[i*2],pubKeyStr[i*2+1],'\0'};
    theirPubKey[i]=(uint8_t)strtol(b,nullptr,16);
  }
  uint8_t sk[AES_KEY_SIZE];
  if (!computeSharedSecretFromPubKey(theirPubKey,sk)) return 0;
  memcpy(sharedKeyOut,sk,AES_KEY_SIZE);
  return nodeId;
}

// =============================================================
//  SECTION 3 — CONTACTS
// =============================================================
int countContacts(){int n=0;for(int i=0;i<MAX_CONTACTS;i++)if(contacts[i].valid)n++;return n;}
bool isContact(uint32_t id){for(int i=0;i<MAX_CONTACTS;i++)if(contacts[i].valid&&contacts[i].nodeId==id)return true;return false;}
String getContactName(uint32_t id){
  for(int i=0;i<MAX_CONTACTS;i++)if(contacts[i].valid&&contacts[i].nodeId==id)return String(contacts[i].name);
  char d[12];sprintf(d,"%08X",id);return String(d);
}
bool addContact(uint32_t nodeId,uint8_t* sharedKey,String name){
  for(int i=0;i<MAX_CONTACTS;i++){
    if(contacts[i].valid&&contacts[i].nodeId==nodeId){
      memcpy(contacts[i].sharedKey,sharedKey,AES_KEY_SIZE);
      contacts[i].verified=false; // key changed on re-pair — a prior verification must not carry over
      if(name.length()>0)name.toCharArray(contacts[i].name,CONTACT_NAME_LEN);
      contacts[i].pairedAt=millis();saveContacts();return true;
    }
  }
  for(int i=0;i<MAX_CONTACTS;i++){
    if(!contacts[i].valid){
      contacts[i].nodeId=nodeId;contacts[i].valid=true;contacts[i].verified=false;contacts[i].pairedAt=millis();
      memcpy(contacts[i].sharedKey,sharedKey,AES_KEY_SIZE);
      if(name.length()==0){char d[10];sprintf(d,"Node%04X",(uint16_t)(nodeId&0xFFFF));name=String(d);}
      name.toCharArray(contacts[i].name,CONTACT_NAME_LEN);
      saveContacts();return true;
    }
  }
  return false;
}
bool removeContact(uint32_t nodeId){
  for(int i=0;i<MAX_CONTACTS;i++){
    if(contacts[i].valid&&contacts[i].nodeId==nodeId){
      contacts[i].valid=false;memset(contacts[i].sharedKey,0,AES_KEY_SIZE);saveContacts();return true;
    }
  }
  return false;
}
bool renameContact(uint32_t nodeId,String name){
  name.trim();if(name.length()==0)return false;
  for(int i=0;i<MAX_CONTACTS;i++){
    if(contacts[i].valid&&contacts[i].nodeId==nodeId){
      name.toCharArray(contacts[i].name,CONTACT_NAME_LEN);saveContacts();return true;
    }
  }
  return false;
}
void saveContacts(){
  Preferences cp;cp.begin("contacts",false);cp.putInt("count",countContacts());
  int slot=0;
  for(int i=0;i<MAX_CONTACTS;i++){
    if(!contacts[i].valid)continue;
    char key[16];
    sprintf(key,"c%d_id",slot);cp.putUInt(key,contacts[i].nodeId);
    sprintf(key,"c%d_key",slot);cp.putBytes(key,contacts[i].sharedKey,AES_KEY_SIZE);
    sprintf(key,"c%d_name",slot);cp.putString(key,contacts[i].name);
    sprintf(key,"c%d_ver",slot);cp.putBool(key,contacts[i].verified);
    slot++;
  }
  cp.end();
}
void loadContacts(){
  for(int i=0;i<MAX_CONTACTS;i++)contacts[i].valid=false;
  Preferences cp;cp.begin("contacts",true);
  int count=cp.getInt("count",0);
  for(int i=0;i<count&&i<MAX_CONTACTS;i++){
    char key[16];
    sprintf(key,"c%d_id",i);uint32_t id=cp.getUInt(key,0);
    if(id==0)continue;
    contacts[i].nodeId=id;contacts[i].valid=true;contacts[i].pairedAt=0;
    sprintf(key,"c%d_key",i);cp.getBytes(key,contacts[i].sharedKey,AES_KEY_SIZE);
    sprintf(key,"c%d_name",i);String nm=cp.getString(key,"");nm.toCharArray(contacts[i].name,CONTACT_NAME_LEN);
    sprintf(key,"c%d_ver",i);contacts[i].verified=cp.getBool(key,false); // absent key => unverified (backward-compatible)
  }
  cp.end();
  Serial.printf("[Contacts] Loaded %d\n",countContacts());
}
int countRooms(){int n=0;for(int i=0;i<MAX_ROOMS;i++)if(rooms[i].valid)n++;return n;}
int findRoom(uint32_t id){for(int i=0;i<MAX_ROOMS;i++)if(rooms[i].valid&&rooms[i].roomId==id)return i;return -1;}
bool getRoomKey(uint32_t id,uint8_t* out){int i=findRoom(id);if(i<0)return false;memcpy(out,rooms[i].key,AES_KEY_SIZE);return true;}
void saveRooms(){
  Preferences rp;rp.begin("rooms",false);rp.putInt("count",countRooms());
  int slot=0;
  for(int i=0;i<MAX_ROOMS;i++){
    if(!rooms[i].valid)continue;
    char k[16];
    sprintf(k,"r%d_id",slot);rp.putUInt(k,rooms[i].roomId);
    sprintf(k,"r%d_key",slot);rp.putBytes(k,rooms[i].key,AES_KEY_SIZE);
    sprintf(k,"r%d_nm",slot);rp.putString(k,rooms[i].name);
    sprintf(k,"r%d_mc",slot);rp.putUChar(k,rooms[i].memberCount);
    if(rooms[i].memberCount>0){sprintf(k,"r%d_mem",slot);rp.putBytes(k,rooms[i].members,rooms[i].memberCount*4);}
    slot++;
  }
  rp.end();
}
void loadRooms(){
  for(int i=0;i<MAX_ROOMS;i++){rooms[i].valid=false;rooms[i].memberCount=0;}
  Preferences rp;rp.begin("rooms",true);
  int count=rp.getInt("count",0);
  for(int i=0;i<count&&i<MAX_ROOMS;i++){
    char k[16];
    sprintf(k,"r%d_id",i);uint32_t id=rp.getUInt(k,0);
    if(id==0)continue;
    rooms[i].roomId=id;rooms[i].valid=true;
    sprintf(k,"r%d_key",i);rp.getBytes(k,rooms[i].key,AES_KEY_SIZE);
    sprintf(k,"r%d_nm",i);String nm=rp.getString(k,"");nm.toCharArray(rooms[i].name,ROOM_NAME_LEN);
    sprintf(k,"r%d_mc",i);rooms[i].memberCount=rp.getUChar(k,0);
    if(rooms[i].memberCount>MAX_ROOM_MEMBERS)rooms[i].memberCount=MAX_ROOM_MEMBERS;
    if(rooms[i].memberCount>0){sprintf(k,"r%d_mem",i);rp.getBytes(k,rooms[i].members,rooms[i].memberCount*4);}
  }
  rp.end();
  Serial.printf("[Rooms] Loaded %d\n",countRooms());
}
bool addRoom(uint32_t id,uint8_t* key,const char* name,bool priv,uint8_t maxM){
  int i=findRoom(id);bool isNew=false;
  if(i<0){for(int j=0;j<MAX_ROOMS;j++)if(!rooms[j].valid){i=j;isNew=true;break;}}
  if(i<0)return false;
  rooms[i].roomId=id;memcpy(rooms[i].key,key,AES_KEY_SIZE);
  strncpy(rooms[i].name,name,ROOM_NAME_LEN-1);rooms[i].name[ROOM_NAME_LEN-1]=0;rooms[i].valid=true;
  rooms[i].isPrivate=priv;rooms[i].maxMsgs=maxM?maxM:50;
  if(isNew)rooms[i].memberCount=0;
  saveRooms();return true;
}
void addRoomMember(uint32_t roomId,uint32_t nodeId){
  int ri=findRoom(roomId);if(ri<0||nodeId==0)return;
  for(int i=0;i<rooms[ri].memberCount;i++)if(rooms[ri].members[i]==nodeId)return;
  if(rooms[ri].memberCount<MAX_ROOM_MEMBERS){rooms[ri].members[rooms[ri].memberCount++]=nodeId;saveRooms();}
}
String roomMembersStr(int ri){
  String s="";uint32_t myId=getMyNodeId();
  for(int i=0;i<rooms[ri].memberCount;i++){
    uint32_t mid=rooms[ri].members[i];String nm;
    if(mid==myId)nm="You";
    else if(isContact(mid))nm=getContactName(mid);
    else{char h[12];sprintf(h,"%08X",mid);nm=String(h);}
    if(s.length()>0)s+=", ";s+=nm;
  }
  return s;
}
bool deleteRoom(uint32_t id){int i=findRoom(id);if(i<0)return false;rooms[i].valid=false;saveRooms();return true;}

// =============================================================
//  SECTION 4 — LICENCE (Ed25519 — verified via PLSChatLicence.h)
// =============================================================
bool validateAndSaveLicence(String ls) {
  ls.trim();
  String tier; uint32_t expiry;
  if (!verifyLicenceString(ls, tier, expiry)) return false;
  licenceSave(ls, tier, expiry);
  licState.valid  = true;
  licState.tier   = tier;
  licState.expiry = expiry;
  licState.raw    = ls;
  isLicensed    = true;
  licenceExpiry = expiry;
  licenceKey    = ls;
  return true;
}
void loadLicence() {
  licenceLoad();                  // loads from NVS and verifies Ed25519 sig
  isLicensed    = licState.valid;
  licenceExpiry = licState.expiry;
  licenceKey    = licState.raw;
}
// Returns days remaining on the licence, or -1 if unknown (no time sync yet / unlicensed).
// See the timeSyncEpoch comment above for accuracy notes — this is a display estimate,
// not the source of truth (that lives server-side / in the signed licence itself).
long getDaysLeft(){
  if(!isLicensed||licenceExpiry==0)return -1;
  if(!timeSynced)return -1;
  unsigned long elapsedSinceSync=lifetimeSeconds-timeSyncLifetimeSecs; // seconds device has been on since sync
  uint32_t estNow=timeSyncEpoch+(uint32_t)elapsedSinceSync;
  if(estNow>=licenceExpiry)return 0;
  return (long)((licenceExpiry-estNow)/86400UL);
}
String getDaysLeftString(){
  long d=getDaysLeft();
  if(d<0)return "N/A";
  if(d==0)return "EXPIRED";
  return String(d)+"d";
}
bool validateStoredLicence() {
  return licState.valid;
}

// =============================================================
//  SECTION 5 — CRYPTO
// =============================================================
void derivePublicChannelKey(){
  mbedtls_sha256_context sha;mbedtls_sha256_init(&sha);mbedtls_sha256_starts(&sha,0);
  mbedtls_sha256_update(&sha,(const unsigned char*)PUBLIC_CHANNEL_PASSPHRASE,strlen(PUBLIC_CHANNEL_PASSPHRASE));
  mbedtls_sha256_finish(&sha,publicChannelKey);mbedtls_sha256_free(&sha);
}
void generateKeyPair(){
  mbedtls_ecp_group grp;mbedtls_mpi d;mbedtls_ecp_point Q;
  mbedtls_ecp_group_init(&grp);mbedtls_mpi_init(&d);mbedtls_ecp_point_init(&Q);
  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
  mbedtls_ecp_gen_keypair(&grp, &d, &Q, mbedtls_ctr_drbg_random, &ctrDrbg);
  mbedtls_mpi_write_binary(&d, myPrivateKey, CURVE25519_KEY_SIZE);
  unsigned char ptBuf[100]; size_t ptLen = 0;
  mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &ptLen, ptBuf, sizeof(ptBuf));
  int xOffset = (ptLen > 32) ? (ptLen - 2*CURVE25519_KEY_SIZE) : 0;
  memcpy(myPublicKey, ptBuf + xOffset, CURVE25519_KEY_SIZE);
  mbedtls_ecp_group_free(&grp);mbedtls_mpi_free(&d);mbedtls_ecp_point_free(&Q);
  prefs.putBytes("privKey", myPrivateKey, CURVE25519_KEY_SIZE);
  prefs.putBytes("pubKey",  myPublicKey,  CURVE25519_KEY_SIZE);
  Serial.println("[Crypto] New key pair generated");
}
void loadOrGenerateKeyPair(){
  if(prefs.getBytesLength("privKey")==CURVE25519_KEY_SIZE&&prefs.getBytesLength("pubKey")==CURVE25519_KEY_SIZE){
    prefs.getBytes("privKey",myPrivateKey,CURVE25519_KEY_SIZE);
    prefs.getBytes("pubKey",myPublicKey,CURVE25519_KEY_SIZE);
    Serial.println("[Crypto] Keys loaded");
  } else generateKeyPair();
}
bool computeSharedSecretFromPubKey(uint8_t* theirPubKey, uint8_t* out){
  bool allZero=true;
  for(int i=0;i<CURVE25519_KEY_SIZE;i++)if(theirPubKey[i]!=0){allZero=false;break;}
  if(allZero){Serial.println("[Crypto] computeShared: zero pubkey");return false;}
  mbedtls_ecp_group grp;mbedtls_mpi d;mbedtls_ecp_point Qp, result;
  mbedtls_ecp_group_init(&grp);mbedtls_mpi_init(&d);mbedtls_ecp_point_init(&Qp);mbedtls_ecp_point_init(&result);
  bool ok=false;
  do {
    if(mbedtls_ecp_group_load(&grp,MBEDTLS_ECP_DP_CURVE25519)!=0){Serial.println("[Crypto] group_load failed");break;}
    if(mbedtls_mpi_read_binary(&d,myPrivateKey,CURVE25519_KEY_SIZE)!=0){Serial.println("[Crypto] privkey load failed");break;}
    unsigned char ptBuf[65];ptBuf[0]=0x04;
    memcpy(ptBuf+1, theirPubKey, CURVE25519_KEY_SIZE);
    memcpy(ptBuf+33, theirPubKey, CURVE25519_KEY_SIZE);
    if(mbedtls_ecp_point_read_binary(&grp,&Qp,ptBuf,65)!=0){
      if(mbedtls_ecp_point_read_binary(&grp,&Qp,theirPubKey,32)!=0){Serial.println("[Crypto] point_read failed");break;}
    }
    if(mbedtls_ecp_mul(&grp,&result,&d,&Qp,mbedtls_ctr_drbg_random,&ctrDrbg)!=0){Serial.println("[Crypto] ecp_mul failed");break;}
    unsigned char rBuf[100]; size_t rLen=0;
    if(mbedtls_ecp_point_write_binary(&grp,&result,MBEDTLS_ECP_PF_UNCOMPRESSED,&rLen,rBuf,sizeof(rBuf))!=0){Serial.println("[Crypto] point_write failed");break;}
    unsigned char shared[CURVE25519_KEY_SIZE]={0};
    if(rLen>=CURVE25519_KEY_SIZE+1)memcpy(shared,rBuf+1,CURVE25519_KEY_SIZE);
    else memcpy(shared,rBuf,CURVE25519_KEY_SIZE);
    mbedtls_sha256_context sha;mbedtls_sha256_init(&sha);mbedtls_sha256_starts(&sha,0);
    mbedtls_sha256_update(&sha,shared,CURVE25519_KEY_SIZE);mbedtls_sha256_finish(&sha,out);mbedtls_sha256_free(&sha);
    ok=true;Serial.println("[Crypto] computeShared OK");
  } while(0);
  mbedtls_ecp_group_free(&grp);mbedtls_mpi_free(&d);mbedtls_ecp_point_free(&Qp);mbedtls_ecp_point_free(&result);
  return ok;
}
void initCrypto(){
  unsigned long t0=millis();Serial.println("[Crypto] Initialising...");
  mbedtls_entropy_init(&entropy);mbedtls_ctr_drbg_init(&ctrDrbg);
  const char* pers="plschat_rng";
  if(mbedtls_ctr_drbg_seed(&ctrDrbg,mbedtls_entropy_func,&entropy,(const unsigned char*)pers,strlen(pers))!=0){Serial.println("[Crypto] RNG FAILED");return;}
  bool keysExist=(prefs.getBytesLength("privKey")==CURVE25519_KEY_SIZE);
  if(!keysExist){Serial.println("[Crypto] Generating new key pair (first boot)...");u8g2.clearBuffer();u8g2.setFont(u8g2_font_5x7_tr);u8g2.drawStr(5,20,"Generating crypto keys");u8g2.drawStr(5,32,"First boot only ~3s");u8g2.sendBuffer();}
  derivePublicChannelKey();loadOrGenerateKeyPair();cryptoReady=true;
  Serial.printf("[Crypto] Ready in %lums. NodeID:%08X\n",millis()-t0,getMyNodeId());
}
bool getSharedKey(uint32_t id,uint8_t* out){
  for(int i=0;i<MAX_CONTACTS;i++)if(contacts[i].valid&&contacts[i].nodeId==id){memcpy(out,contacts[i].sharedKey,AES_KEY_SIZE);return true;}
  return false;
}
void storeSharedKey(uint32_t id,uint8_t* key){
  for(int i=0;i<MAX_CONTACTS;i++)if(contacts[i].valid&&contacts[i].nodeId==id){
    memcpy(contacts[i].sharedKey,key,AES_KEY_SIZE);
    contacts[i].verified=false; // shared key rotated (fresh handshake could be an attacker) -> force re-verify
    saveContacts();             // persist the reset; call sites are pairing/rotation events, not hot loops
    return;
  }
}

// ================= SAFETY-WORD VERIFICATION (v2.50) =================
// Six words derived deterministically from the ECDH shared key, which is
// byte-identical on both paired devices. Both ends therefore produce the
// SAME six words in the SAME order with nothing transmitted. Users read them
// aloud over a trusted channel to detect a man-in-the-middle. The words are
// derived from a domain-separated hash, never from the live key bytes directly.
static const char* const SAFETY_WORDS[256] = {
  "acid", "acorn", "actor", "afraid", "agent", "album", "alert", "alien",
  "alpha", "amber", "angel", "ankle", "apple", "apron", "arch", "arctic",
  "arena", "armor", "arrow", "atlas", "attic", "audio", "autumn", "axle",
  "bacon", "badge", "bagel", "baker", "balloon", "bamboo", "banana", "banjo",
  "barn", "basil", "basin", "batch", "beacon", "beagle", "beam", "bean",
  "bear", "beaver", "bell", "belt", "bench", "berry", "bike", "birch",
  "bison", "black", "blade", "blanket", "blaze", "blimp", "block", "bloom",
  "board", "boat", "bolt", "bonus", "books", "boots", "bottle", "boulder",
  "bounce", "bowl", "brain", "branch", "brass", "brave", "bread", "brick",
  "bridge", "broom", "brush", "bubble", "bucket", "buffalo", "bugle", "bulb",
  "bunny", "burger", "bush", "cabin", "cactus", "cake", "camel", "candle",
  "canoe", "canyon", "cape", "carbon", "cargo", "carpet", "carrot", "castle",
  "cave", "cedar", "cement", "chain", "chair", "chalk", "cheese", "cherry",
  "chess", "chili", "chimp", "cider", "cinema", "circle", "clam", "clay",
  "cliff", "cloak", "clock", "cloud", "clover", "coach", "coast", "cobra",
  "cocoa", "coffee", "comet", "copper", "coral", "corn", "cotton", "cougar",
  "crab", "crane", "crater", "crayon", "cream", "creek", "cricket", "crown",
  "cube", "dagger", "daisy", "dawn", "deer", "delta", "denim", "desert",
  "diamond", "diesel", "dime", "diner", "dolphin", "donut", "dragon", "drum",
  "eagle", "earth", "easel", "echo", "eclipse", "elbow", "ember", "emerald",
  "engine", "eskimo", "ether", "ferry", "fiber", "fig", "finch", "flag",
  "flame", "flask", "float", "flute", "foam", "forest", "fossil", "fox",
  "frame", "frost", "fudge", "galaxy", "garden", "garlic", "gecko", "gem",
  "ginger", "glass", "glove", "goose", "grain", "grape", "grass", "gravel",
  "grill", "grove", "guitar", "hammer", "harbor", "harp", "hawk", "hazel",
  "helmet", "hero", "honey", "horse", "hotel", "hyena", "ice", "igloo",
  "indigo", "iris", "iron", "island", "ivory", "jacket", "jaguar", "jazz",
  "jelly", "jetty", "jewel", "jungle", "kayak", "kettle", "kiwi", "koala",
  "label", "ladder", "lagoon", "lamp", "lantern", "lark", "lava", "leaf",
  "lemon", "lever", "lilac", "lime", "linen", "lion", "llama", "lobby",
  "lock", "locust", "lotus", "lumber", "lunar", "magma", "mango", "maple",
  "marble", "marsh", "mask", "meadow", "medal", "melon", "meteor", "mint",
};
// Domain-separated derivation of six safety words from the contact's shared key.
String getSafetyWords(uint32_t nodeId){
  uint8_t sk[AES_KEY_SIZE];
  if(!getSharedKey(nodeId,sk))return String("");
  static const char* TAG="PLSCHAT-SAFETY-WORDS-v1";
  uint8_t dig[32];
  mbedtls_sha256_context sha;mbedtls_sha256_init(&sha);mbedtls_sha256_starts(&sha,0);
  mbedtls_sha256_update(&sha,(const unsigned char*)TAG,strlen(TAG));
  mbedtls_sha256_update(&sha,sk,AES_KEY_SIZE);
  mbedtls_sha256_finish(&sha,dig);mbedtls_sha256_free(&sha);
  memset(sk,0,AES_KEY_SIZE); // don't leave key material on the stack
  String out;
  for(int i=0;i<6;i++){ if(i)out+=" "; out+=SAFETY_WORDS[dig[i]]; }
  return out;
}
bool isContactVerified(uint32_t nodeId){
  for(int i=0;i<MAX_CONTACTS;i++)if(contacts[i].valid&&contacts[i].nodeId==nodeId)return contacts[i].verified;
  return false;
}
void setContactVerified(uint32_t nodeId,bool v){
  for(int i=0;i<MAX_CONTACTS;i++)if(contacts[i].valid&&contacts[i].nodeId==nodeId){contacts[i].verified=v;saveContacts();return;}
}
// =================================================================

// =============================================================
//  SECTION 6 — AES-256-CBC
// =============================================================
bool encryptAES256(uint8_t* key,uint8_t* iv,uint8_t* pt,int len,uint8_t* ct){
  if(len<=0||len>256||len%AES_BLOCK_SIZE!=0)return false;
  mbedtls_aes_context aes;mbedtls_aes_init(&aes);
  if(mbedtls_aes_setkey_enc(&aes,key,256)!=0){mbedtls_aes_free(&aes);return false;}
  uint8_t ivc[AES_IV_SIZE];memcpy(ivc,iv,AES_IV_SIZE);
  int r=mbedtls_aes_crypt_cbc(&aes,MBEDTLS_AES_ENCRYPT,len,ivc,pt,ct);
  mbedtls_aes_free(&aes);return r==0;
}
int decryptAES256(uint8_t* key,uint8_t* iv,uint8_t* ct,int cl,uint8_t* pt){
  if(cl<=0||cl>256||cl%AES_BLOCK_SIZE!=0)return -1;
  mbedtls_aes_context aes;mbedtls_aes_init(&aes);
  if(mbedtls_aes_setkey_dec(&aes,key,256)!=0){mbedtls_aes_free(&aes);return -1;}
  uint8_t ivc[AES_IV_SIZE];memcpy(ivc,iv,AES_IV_SIZE);
  int r=mbedtls_aes_crypt_cbc(&aes,MBEDTLS_AES_DECRYPT,cl,ivc,ct,pt);
  mbedtls_aes_free(&aes);if(r!=0)return -1;
  return cl;
}

// =============================================================
//  MESSAGE ALERTS (v2.53) — beep / flash / vibrate on new messages
// =============================================================
// Wiring (see PLSChat alert build sheet):
//   Buzzer  : PS1240 piezo. ALERT_BUZZER_PIN -> 100R -> buzzer -> GND.
//   Motor   : coin motor via PN2222. ALERT_MOTOR_PIN -> 1k -> base;
//             emitter -> GND; collector -> motor(-); motor(+) -> 3V3;
//             1N4148 across the motor, stripe to 3V3.
//   LED     : the board's own built-in LED.
// Set a pin to -1 if that part is not fitted. Every output is also
// switchable from the web UI (Settings -> Message alerts).
// Heltec WiFi LoRa 32 V4 pins. Checked against the V4 pin map: GPIO2/5/7/46
// belong to the radio front-end (FEM) and must NOT be used; 47/48 are free.
#define ALERT_LED_ON     HIGH      // built-in white LED (GPIO35) lights when HIGH
#define ALERT_BUZZER_PIN 47        // -1 if no buzzer fitted
#define ALERT_MOTOR_PIN  48        // -1 if no motor fitted
#define ALERT_REMIND_MS  15000UL   // unread reminder blip interval
bool alertLedOn   = true;
bool alertBuzzOn  = true;
bool alertVibOn   = true;
bool alertPubOn   = false;          // also alert on PUBLIC channel messages
bool alertUnread  = false;
struct AlertStep { uint16_t ms; uint8_t led; uint16_t hz; uint8_t vib; };
// Private / room message: rising three-tone chirp + 3 buzzes
static const AlertStep ALERT_PRIV[] = {{160,1,3000,1},{110,0,0,0},{160,1,4000,1},{110,0,0,0},{260,1,5000,1},{0,0,0,0}};
// Public channel message: one short blip
static const AlertStep ALERT_PUB[]  = {{120,1,4000,1},{0,0,0,0}};
// Unread reminder: tiny LED blip only
static const AlertStep ALERT_BLIP[] = {{60,1,0,0},{0,0,0,0}};
const AlertStep* alertSeq = nullptr;
int           alertIdx     = 0;
unsigned long alertStepAt  = 0;
unsigned long alertLastRemind = 0;
bool          alertForce   = false;   // test mode: ignore the on/off toggles

void alertOutputs(bool led, uint16_t hz, bool vib){
  bool L = led && (alertLedOn  || alertForce);
  bool B = hz  && (alertBuzzOn || alertForce);
  bool V = vib && (alertVibOn  || alertForce);
  digitalWrite(WHITE_LED, L ? ALERT_LED_ON : !ALERT_LED_ON);
  if(ALERT_BUZZER_PIN >= 0){ if(B) tone(ALERT_BUZZER_PIN, hz); else noTone(ALERT_BUZZER_PIN); }
  if(ALERT_MOTOR_PIN  >= 0) digitalWrite(ALERT_MOTOR_PIN, V ? HIGH : LOW);
}
void alertInit(){
  if(ALERT_MOTOR_PIN  >= 0){ pinMode(ALERT_MOTOR_PIN, OUTPUT); digitalWrite(ALERT_MOTOR_PIN, LOW); }
  if(ALERT_BUZZER_PIN >= 0){ pinMode(ALERT_BUZZER_PIN, OUTPUT); digitalWrite(ALERT_BUZZER_PIN, LOW); }
}
void alertLoadPrefs(){
  alertLedOn  = prefs.getBool("alLed",  true);
  alertBuzzOn = prefs.getBool("alBuzz", true);
  alertVibOn  = prefs.getBool("alVib",  true);
  alertPubOn  = prefs.getBool("alPub",  false);
}
void alertStart(const AlertStep* seq, bool force=false){
  alertSeq = seq; alertIdx = 0; alertForce = force; alertStepAt = millis();
  alertOutputs(seq[0].led, seq[0].hz, seq[0].vib);
}
// Non-blocking: call every loop. Never delays the radio or web server.
void alertLoop(){
  unsigned long now = millis();
  if(alertSeq){
    if(now - alertStepAt >= alertSeq[alertIdx].ms){
      alertIdx++; alertStepAt = now;
      if(alertSeq[alertIdx].ms == 0){ alertOutputs(false,0,false); alertSeq = nullptr; alertForce = false; }
      else alertOutputs(alertSeq[alertIdx].led, alertSeq[alertIdx].hz, alertSeq[alertIdx].vib);
    }
    return;
  }
  if(alertUnread && alertLedOn && now - alertLastRemind >= ALERT_REMIND_MS){
    alertLastRemind = now; alertStart(ALERT_BLIP);
  }
}
void alertOnMessage(bool privOrRoom){
  if(!privOrRoom && !alertPubOn) return;
  alertUnread = true; alertLastRemind = millis();
  alertStart(privOrRoom ? ALERT_PRIV : ALERT_PUB);
  lastOledActivity = millis(); wakeOLED();   // light the screen so "NEW!" is visible
}
void alertClearUnread(){ alertUnread = false; }

// =============================================================
//  SECTION 7 — MESSAGE STORE
// =============================================================
void storeMessage(uint32_t from,bool priv,bool me,const char* text,uint32_t to=0,uint32_t room=0,uint32_t msgId=0){
  ChatMessage& m=messageStore[messageHead];
  m.fromNode=from;m.isPrivate=priv;m.isMe=me;m.toNode=to;m.roomId=room;m.msgId=msgId;m.status=0;m.timestamp=millis();
  strncpy(m.text,text,MAX_MSG_LEN-1);m.text[MAX_MSG_LEN-1]='\0';
  messageHead=(messageHead+1)%MAX_MESSAGES;
  if(messageCount<MAX_MESSAGES)messageCount++;
  newMessageFlag=true;messagesDirty=true;
  if(!me)alertOnMessage(priv||room!=0);
  Serial.printf("[MSG] %s from=%08X to=%08X\n",priv?"PRIV":"PUB",from,to);
}

// =============================================================
//  SECTION 8 — KEY EXCHANGE
// =============================================================
void sendKeyExchangePacket(uint32_t destId,uint8_t pktType){
  if(!loraReady||!cryptoReady)return;
  uint32_t myId=getMyNodeId();
  uint8_t pkt[41];
  pkt[0]=pktType;
  pkt[1]=(myId>>24)&0xFF;pkt[2]=(myId>>16)&0xFF;pkt[3]=(myId>>8)&0xFF;pkt[4]=myId&0xFF;
  pkt[5]=(destId>>24)&0xFF;pkt[6]=(destId>>16)&0xFF;pkt[7]=(destId>>8)&0xFF;pkt[8]=destId&0xFF;
  memcpy(&pkt[9],myPublicKey,CURVE25519_KEY_SIZE);
  delay(random(10,50));radio.startTransmit(pkt,sizeof(pkt));
}
void handleKeyExchange(uint8_t* buf,int len){
  if(len<41)return;
  uint32_t srcId=((uint32_t)buf[1]<<24)|((uint32_t)buf[2]<<16)|((uint32_t)buf[3]<<8)|(uint32_t)buf[4];
  uint32_t dstId=((uint32_t)buf[5]<<24)|((uint32_t)buf[6]<<16)|((uint32_t)buf[7]<<8)|(uint32_t)buf[8];
  if(dstId!=getMyNodeId())return;
  if(isContact(srcId)){uint8_t sk[AES_KEY_SIZE];if(computeSharedSecretFromPubKey(&buf[9],sk))storeSharedKey(srcId,sk);}
  if(buf[0]==PKT_TYPE_KEY_REQ){delay(random(50,150));sendKeyExchangePacket(srcId,PKT_TYPE_KEY_ACK);}
}

// =============================================================
//  SECTION 9 — BLE
// =============================================================
class MySecurityCallbacks:public BLESecurityCallbacks{
  uint32_t onPassKeyRequest()override{return(uint32_t)blePin.toInt();}
  void onPassKeyNotify(uint32_t)override{}
  bool onConfirmPIN(uint32_t p)override{return(uint32_t)blePin.toInt()==p;}
  bool onSecurityRequest()override{return true;}
};
class MyCallbacks:public BLECharacteristicCallbacks{
  void onWrite(BLECharacteristic* ch)override{
    String v=ch->getValue().c_str();v.trim();v.toUpperCase();
    if(v.indexOf("WIFI")!=-1&&!wifiEnabled){wifiEnabled=true;prefs.putBool("wifiOn",true);applyMode();}
    else if(v.indexOf("BLE")!=-1&&!bleEnabled){bleEnabled=true;prefs.putBool("bleOn",true);applyMode();}
  }
};

// =============================================================
//  SECTION 10 — BUTTON ISR
// =============================================================
void IRAM_ATTR btnISR(){
  unsigned long now=millis();
  if(digitalRead(BTN_PIN)==LOW){if(now-lastBtnTime>200){btnDown=true;btnPressTime=now;btnLongHandled=false;}}
  else{if(btnDown&&!btnLongHandled&&(now-btnPressTime<LONG_PRESS_MS))btnPressed=true;btnDown=false;lastBtnTime=now;}
}

// =============================================================
//  SECTION 11 — CHARGING / BATTERY
// =============================================================
bool getChargingState(){
  static float v1=0,v2=0;static bool ch=false,usb=false;static unsigned long ls=0;
  if(millis()-ls<1000)return ch;ls=millis();
  float v=readVbatMv();if(v1==0){v1=v;v2=v;return ch;}
  float d2=v-v2,d1=v-v1;v2=v1;v1=v;
  if(d1<-25){ch=false;usb=false;return false;}
  if(d2>6){ch=true;usb=true;return true;}
  if(usb&&ch&&v>=4175){ch=false;return false;}
  if(usb&&!ch&&batPct<=90){ch=true;return true;}
  return ch;
}
float readVbatMv(){
  // Heltec WiFi LoRa 32 V3: ADC_Ctrl (GPIO37) is ACTIVE-LOW. Pull it LOW to
  // connect the battery divider to VBAT_Read (GPIO1), sample, then release it.
  pinMode(ADC_CTRL_PIN,OUTPUT);digitalWrite(ADC_CTRL_PIN,LOW);delay(10);
  analogSetAttenuation(ADC_11db);long sum=0;
  for(int i=0;i<32;i++){sum+=analogReadMilliVolts(VBAT_PIN);delay(1);}  // eFuse-calibrated pin mV
  digitalWrite(ADC_CTRL_PIN,HIGH);pinMode(ADC_CTRL_PIN,INPUT);          // divider off (saves power)
  return (sum/32.0f)*batDivider;                                        // scale pin mV up to battery mV
}
int getBatteryPercent(){
  float v=readVbatMv();
  if(batLiFePO4){
    // LiFePO4 flat discharge curve
    static const float vt[]={2800,2950,3050,3100,3150,3180,3200,3220,3240,3260,3280,3300,3320,3350,3400,3450,3500,3550,3600};
    static const int   pt[]={0,2,5,10,18,25,35,45,55,62,68,74,80,86,91,95,97,99,100};
    const int n=19;if(v<=vt[0])return 0;if(v>=vt[n-1])return 100;
    for(int i=1;i<n;i++)if(v<=vt[i]){float f=(v-vt[i-1])/(vt[i]-vt[i-1]);return(int)(pt[i-1]+f*(pt[i]-pt[i-1]));}
    return 100;
  }
  // Standard LiPo/Li-ion with configurable min/max voltage
  if(v<=batMinMv)return 0;if(v>=batMaxMv)return 100;
  // Scale reading to standard 3000-4180mV reference curve
  float vS=3000.0f+(v-batMinMv)*(4180.0f-3000.0f)/(batMaxMv-batMinMv);
  static const float vt[]={3000,3200,3400,3500,3600,3650,3700,3740,3780,3820,3870,3920,3970,4020,4060,4100,4130,4160,4180};
  static const int   pt[]={0,3,7,11,17,22,28,34,41,48,56,64,71,78,84,89,93,97,100};
  const int n=19;if(vS<=vt[0])return 0;if(vS>=vt[n-1])return 100;
  for(int i=1;i<n;i++)if(vS<=vt[i]){float f=(vS-vt[i-1])/(vt[i]-vt[i-1]);return(int)(pt[i-1]+f*(pt[i]-pt[i-1]));}
  return 100;
}

// =============================================================
//  SECTION 12 — UPTIME / RSSI
// =============================================================
void tickUptime(){if(millis()-lastUptimeTick>=1000){uptimeSeconds++;lifetimeSeconds++;lastUptimeTick=millis();}}
String getUptimeString(){char b[8];sprintf(b,"%02dh%02dm",(int)(uptimeSeconds/3600),(int)((uptimeSeconds%3600)/60));return b;}
String getLifetimeString(){
  unsigned long s=lifetimeSeconds;int d=s/86400,h=(s%86400)/3600,m=(s%3600)/60;
  char b[16];sprintf(b,d>0?"%dd%02dh%02dm":"%02dh%02dm",d,h,m);return b;
}
void updateRSSI(){
  if(millis()-lastRSSITime>=1000){
    lastRSSITime=millis();
    wifi_sta_list_t sl;memset(&sl,0,sizeof(sl));esp_wifi_ap_get_sta_list(&sl);
    clientCount=sl.num;
    if(clientCount>0){int best=-99;for(int i=0;i<clientCount;i++)if(sl.sta[i].rssi>best)best=sl.sta[i].rssi;currentRSSI=best;}
    else currentRSSI=-99;
  }
  if(millis()-lastRSSIHistory>=2000){
    rssiHistory[rssiIndex]=(clientCount>0)?currentRSSI:-99;
    rssiIndex=(rssiIndex+1)%RSSI_HISTORY;if(rssiIndex==0)rssiHistoryFull=true;
    lastRSSIHistory=millis();
  }
}

// =============================================================
//  SECTION 13 — SETTINGS MODE
// =============================================================
void enterSettingsMode(){
  settingsMode=true;settingsModeStart=millis();
  prevModeWasBLE=bleEnabled&&!wifiEnabled;wifiEnabled=true;applyMode();
  u8g2.clearBuffer();u8g2.setFont(u8g2_font_7x13B_tr);u8g2.drawStr(5,18,"SETTINGS MODE");
  u8g2.setFont(u8g2_font_5x7_tr);
  u8g2.drawStr(0,32,("WiFi: "+wifiSSID).c_str());
  u8g2.drawStr(0,42,("Pass: "+wifiPass).c_str());
  u8g2.drawStr(0,52,"http://192.168.4.1");
  u8g2.drawStr(0,62,"Auto-exit: 5 mins");
  u8g2.sendBuffer();delay(3000);updateOLED();
}
void exitSettingsMode(){
  settingsMode=false;if(prevModeWasBLE){wifiEnabled=false;bleEnabled=true;}
  applyMode();u8g2.clearBuffer();u8g2.setFont(u8g2_font_7x13B_tr);u8g2.drawStr(15,25,"Settings");
  u8g2.setFont(u8g2_font_5x7_tr);u8g2.drawStr(25,42,"Saved!");u8g2.drawStr(10,58,"Returning...");
  u8g2.sendBuffer();delay(2000);updateOLED();
}

// =============================================================
//  SECTION 14 — SAVE / LOAD
// =============================================================
void saveMessages(){
  Preferences mp;if(!mp.begin("msgs",false))return;
  mp.putBytes("store",messageStore,sizeof(messageStore));
  mp.putInt("count",messageCount);mp.putInt("head",messageHead);mp.end();
}
void loadMessages(){
  Preferences mp;if(!mp.begin("msgs",true))return;
  size_t sz=mp.getBytesLength("store");
  if(sz==sizeof(messageStore)){
    mp.getBytes("store",messageStore,sizeof(messageStore));
    messageCount=mp.getInt("count",0);messageHead=mp.getInt("head",0);
    if(messageCount<0||messageCount>MAX_MESSAGES)messageCount=0;
    if(messageHead<0||messageHead>=MAX_MESSAGES)messageHead=0;
  }
  mp.end();
}
void periodicSave(){
  unsigned long now=millis();
  if(messagesDirty && now-lastMsgSave>=4000UL){lastMsgSave=now;messagesDirty=false;saveMessages();}
  if(now-lastSaveTime>=SAVE_INTERVAL_MS){
    lastSaveTime=now;currentSaveSlot=(currentSaveSlot+1)%2;
    String slot=(currentSaveSlot==0)?"slotA":"slotB";
    prefs.putULong((slot+"_uptime").c_str(),uptimeSeconds);
    prefs.putULong((slot+"_time").c_str(),now);
    prefs.putInt("lastSlot",currentSaveSlot);
    prefs.putULong("lifetime",lifetimeSeconds);
    if(timeSynced){prefs.putUInt("tsEpoch",timeSyncEpoch);prefs.putULong("tsLife",timeSyncLifetimeSecs);}
  }
}
#define PUBLIC_FREE_CAP 10
#define PUBLIC_WINDOW_MS 7200000UL
unsigned long pubWindowStart=0;
int pubMsgCount=0;
void loadSavedState(){
  int ls=prefs.getInt("lastSlot",-1);lifetimeSeconds=prefs.getULong("lifetime",0);
  timeSyncEpoch=prefs.getUInt("tsEpoch",0);
  timeSyncLifetimeSecs=prefs.getULong("tsLife",0);
  timeSynced=(timeSyncEpoch>1700000000UL); // sane epoch sanity check (>Nov 2023)
  if(ls==-1)return;String slot=(ls==0)?"slotA":"slotB";
  uptimeSeconds=prefs.getULong((slot+"_uptime").c_str(),0);
  pubMsgCount=prefs.getInt("pubCount",0);
  if(pubMsgCount<0||pubMsgCount>PUBLIC_FREE_CAP)pubMsgCount=0;
}

// =============================================================
//  SECTION 15 — WIFI / BLE
// =============================================================
void startWiFiAP(){WiFi.softAP(wifiSSID.c_str(),wifiPass.c_str());setupWebServer();server.begin();}
void stopWiFiAP(){server.stop();WiFi.softAPdisconnect(true);}
void startBLEServer(){
  BLEDevice::init(bleName.c_str());
  BLEDevice::setSecurityCallbacks(new MySecurityCallbacks());
  BLESecurity* ps=new BLESecurity();
  ps->setAuthenticationMode(ESP_LE_AUTH_BOND);ps->setCapability(ESP_IO_CAP_OUT);
  ps->setInitEncryptionKey(ESP_BLE_ENC_KEY_MASK|ESP_BLE_ID_KEY_MASK);
  pBLEServer=BLEDevice::createServer();
  BLEService* svc=pBLEServer->createService(SERVICE_UUID);
  BLECharacteristic* ch=svc->createCharacteristic(CHARACTERISTIC_UUID,BLECharacteristic::PROPERTY_WRITE);
  ch->setCallbacks(new MyCallbacks());svc->start();
  BLEAdvertising* adv=BLEDevice::getAdvertising();adv->addServiceUUID(SERVICE_UUID);adv->start();
  bleRunning=true;
}
void stopBLEServer(){if(bleRunning){BLEDevice::getAdvertising()->stop();bleRunning=false;}}
void applyMode(){
  if(!wifiEnabled&&!bleEnabled){wifiEnabled=true;prefs.putBool("wifiOn",true);}
  wifiEnabled?startWiFiAP():stopWiFiAP();
  bleEnabled?startBLEServer():stopBLEServer();
  if(oledOn)updateOLED();
}

// =============================================================
//  SECTION 16 — MESSAGES SEND / RECEIVE
// =============================================================
bool consumePublicQuota(){
  if(isLicensed)return true;
  if(millis()-pubWindowStart>=PUBLIC_WINDOW_MS){pubMsgCount=0;pubWindowStart=millis();prefs.putInt("pubCount",0);}
  if(pubMsgCount>=PUBLIC_FREE_CAP)return false;
  pubMsgCount++;prefs.putInt("pubCount",pubMsgCount);return true;
}
int publicQuotaLeft(){
  if(isLicensed)return -1;
  if(millis()-pubWindowStart>=PUBLIC_WINDOW_MS)return PUBLIC_FREE_CAP;
  int left=PUBLIC_FREE_CAP-pubMsgCount;return left<0?0:left;
}
void sendPublicMessage(String text){
  if(!loraReady||!cryptoReady)return;
  uint32_t myId=getMyNodeId();
  uint8_t iv[AES_IV_SIZE];mbedtls_ctr_drbg_random(&ctrDrbg,iv,AES_IV_SIZE);
  uint8_t pt[MAX_MSG_LEN];memset(pt,0,MAX_MSG_LEN);
  int tlen=min((int)text.length(),MAX_MSG_LEN-1);memcpy(pt,text.c_str(),tlen);
  int clen=MAX_MSG_LEN;
  uint8_t ct[256];if(!encryptAES256(publicChannelKey,iv,pt,MAX_MSG_LEN,ct))return;
  uint8_t pkt[256];int idx=0;
  pkt[idx++]=PKT_TYPE_MSG_PUB;
  pkt[idx++]=(myId>>24)&0xFF;pkt[idx++]=(myId>>16)&0xFF;pkt[idx++]=(myId>>8)&0xFF;pkt[idx++]=myId&0xFF;
  pkt[idx++]=0xFF;pkt[idx++]=0xFF;pkt[idx++]=0xFF;pkt[idx++]=0xFF;
  uint32_t pid;mbedtls_ctr_drbg_random(&ctrDrbg,(uint8_t*)&pid,4);
  pkt[idx++]=(pid>>24)&0xFF;pkt[idx++]=(pid>>16)&0xFF;pkt[idx++]=(pid>>8)&0xFF;pkt[idx++]=pid&0xFF;
  pkt[idx++]=3;pkt[idx++]=clen;
  memcpy(&pkt[idx],iv,AES_IV_SIZE);idx+=AES_IV_SIZE;
  memcpy(&pkt[idx],ct,clen);idx+=clen;
  radio.startTransmit(pkt,idx);storeMessage(myId,false,true,text.c_str());
}
void sendPrivateMessage(uint32_t destId,String text){
  if(!loraReady||!cryptoReady)return;
  uint8_t sk[AES_KEY_SIZE];
  if(!getSharedKey(destId,sk)){
    Serial.printf("[MSG] Not paired with %08X\n",destId);
    storeMessage(getMyNodeId(),true,true,"[Not paired — share pairing codes first]");return;
  }
  uint32_t myId=getMyNodeId();
  uint8_t iv[AES_IV_SIZE];mbedtls_ctr_drbg_random(&ctrDrbg,iv,AES_IV_SIZE);
  uint8_t pt[MAX_MSG_LEN];memset(pt,0,MAX_MSG_LEN);
  int tlen=min((int)text.length(),MAX_MSG_LEN-1);memcpy(pt,text.c_str(),tlen);
  int clen=MAX_MSG_LEN;
  uint8_t ct[256];if(!encryptAES256(sk,iv,pt,MAX_MSG_LEN,ct))return;
  uint8_t pkt[256];int idx=0;
  pkt[idx++]=PKT_TYPE_MSG_PRIV;
  pkt[idx++]=(myId>>24)&0xFF;pkt[idx++]=(myId>>16)&0xFF;pkt[idx++]=(myId>>8)&0xFF;pkt[idx++]=myId&0xFF;
  pkt[idx++]=(destId>>24)&0xFF;pkt[idx++]=(destId>>16)&0xFF;pkt[idx++]=(destId>>8)&0xFF;pkt[idx++]=destId&0xFF;
  uint32_t pid;mbedtls_ctr_drbg_random(&ctrDrbg,(uint8_t*)&pid,4);
  pkt[idx++]=(pid>>24)&0xFF;pkt[idx++]=(pid>>16)&0xFF;pkt[idx++]=(pid>>8)&0xFF;pkt[idx++]=pid&0xFF;
  pkt[idx++]=3;pkt[idx++]=clen;
  memcpy(&pkt[idx],iv,AES_IV_SIZE);idx+=AES_IV_SIZE;
  memcpy(&pkt[idx],ct,clen);idx+=clen;
  radio.startTransmit(pkt,idx);storeMessage(myId,true,true,text.c_str(),destId,0,pid);
  Serial.printf("[ACK] sent PRIV pid %08X to %08X\n",pid,destId);
}
void handleIncomingMessage(uint8_t* buf,int len,bool priv){
  if(len<32)return;
  uint32_t src=((uint32_t)buf[1]<<24)|((uint32_t)buf[2]<<16)|((uint32_t)buf[3]<<8)|(uint32_t)buf[4];
  uint32_t dst=((uint32_t)buf[5]<<24)|((uint32_t)buf[6]<<16)|((uint32_t)buf[7]<<8)|(uint32_t)buf[8];
  if(src==getMyNodeId())return;
  if(priv&&dst!=getMyNodeId())return;
  int cl=buf[14];if(len<15+AES_IV_SIZE+cl)return;
  uint8_t* iv=&buf[15];uint8_t* ct=&buf[15+AES_IV_SIZE];
  uint8_t key[AES_KEY_SIZE];
  if(priv){if(!getSharedKey(src,key))return;}
  else memcpy(key,publicChannelKey,AES_KEY_SIZE);
  uint8_t pt[256];int pl=decryptAES256(key,iv,ct,cl,pt);if(pl<=0)return;
  pt[pl]='\0';
  int actualLen=0;for(int i=0;i<pl;i++)if(pt[i]!=0)actualLen=i+1;pt[actualLen]='\0';
  uint32_t inPid=((uint32_t)buf[9]<<24)|((uint32_t)buf[10]<<16)|((uint32_t)buf[11]<<8)|(uint32_t)buf[12];
  storeMessage(src,priv,false,(char*)pt,0,0,inPid);
  if(priv){delay(random(40,90));Serial.printf("[ACK] tx DELIVERED to %08X pid %08X\n",src,inPid);sendAck(src,inPid,PKT_TYPE_DELIVERED);}
  currentScreen=SCREEN_MESSAGES;
}
void sendRoomMessage(uint32_t roomId,String text){
  if(!loraReady||!cryptoReady)return;
  uint8_t rk[AES_KEY_SIZE];if(!getRoomKey(roomId,rk))return;
  uint32_t myId=getMyNodeId();
  uint8_t iv[AES_IV_SIZE];mbedtls_ctr_drbg_random(&ctrDrbg,iv,AES_IV_SIZE);
  uint8_t pt[MAX_MSG_LEN];memset(pt,0,MAX_MSG_LEN);
  int tlen=min((int)text.length(),MAX_MSG_LEN-1);memcpy(pt,text.c_str(),tlen);
  int clen=MAX_MSG_LEN;
  uint8_t ct[256];if(!encryptAES256(rk,iv,pt,MAX_MSG_LEN,ct))return;
  uint8_t pkt[256];int idx=0;
  pkt[idx++]=PKT_TYPE_ROOM_MSG;
  pkt[idx++]=(myId>>24)&0xFF;pkt[idx++]=(myId>>16)&0xFF;pkt[idx++]=(myId>>8)&0xFF;pkt[idx++]=myId&0xFF;
  pkt[idx++]=(roomId>>24)&0xFF;pkt[idx++]=(roomId>>16)&0xFF;pkt[idx++]=(roomId>>8)&0xFF;pkt[idx++]=roomId&0xFF;
  uint32_t pid;mbedtls_ctr_drbg_random(&ctrDrbg,(uint8_t*)&pid,4);
  pkt[idx++]=(pid>>24)&0xFF;pkt[idx++]=(pid>>16)&0xFF;pkt[idx++]=(pid>>8)&0xFF;pkt[idx++]=pid&0xFF;
  pkt[idx++]=3;pkt[idx++]=clen;
  memcpy(&pkt[idx],iv,AES_IV_SIZE);idx+=AES_IV_SIZE;
  memcpy(&pkt[idx],ct,clen);idx+=clen;
  radio.startTransmit(pkt,idx);storeMessage(myId,false,true,text.c_str(),0,roomId);
}
void handleRoomMessage(uint8_t* buf,int len){
  if(len<32)return;
  uint32_t src=((uint32_t)buf[1]<<24)|((uint32_t)buf[2]<<16)|((uint32_t)buf[3]<<8)|(uint32_t)buf[4];
  uint32_t rid=((uint32_t)buf[5]<<24)|((uint32_t)buf[6]<<16)|((uint32_t)buf[7]<<8)|(uint32_t)buf[8];
  if(src==getMyNodeId())return;
  uint8_t rk[AES_KEY_SIZE];if(!getRoomKey(rid,rk))return;
  addRoomMember(rid,src);
  int cl=buf[14];if(len<15+AES_IV_SIZE+cl)return;
  uint8_t* iv=&buf[15];uint8_t* ct=&buf[15+AES_IV_SIZE];
  uint8_t pt[256];int pl=decryptAES256(rk,iv,ct,cl,pt);if(pl<=0)return;
  int actualLen=0;for(int i=0;i<pl;i++)if(pt[i]!=0)actualLen=i+1;pt[actualLen]=0;
  storeMessage(src,false,false,(char*)pt,0,rid);
  currentScreen=SCREEN_MESSAGES;
}
void sendRoomInvite(uint32_t destId,uint32_t roomId){
  if(!loraReady||!cryptoReady)return;
  uint8_t sk[AES_KEY_SIZE];if(!getSharedKey(destId,sk))return;
  int ri=findRoom(roomId);if(ri<0)return;
  uint32_t myId=getMyNodeId();
  uint8_t pt[64];memset(pt,0,64);
  pt[0]=(roomId>>24)&0xFF;pt[1]=(roomId>>16)&0xFF;pt[2]=(roomId>>8)&0xFF;pt[3]=roomId&0xFF;
  memcpy(&pt[4],rooms[ri].key,AES_KEY_SIZE);
  strncpy((char*)&pt[36],rooms[ri].name,ROOM_NAME_LEN-1);
  uint8_t iv[AES_IV_SIZE];mbedtls_ctr_drbg_random(&ctrDrbg,iv,AES_IV_SIZE);
  uint8_t ct[256];if(!encryptAES256(sk,iv,pt,64,ct))return;
  uint8_t pkt[256];int idx=0;
  pkt[idx++]=PKT_TYPE_ROOM_INVITE;
  pkt[idx++]=(myId>>24)&0xFF;pkt[idx++]=(myId>>16)&0xFF;pkt[idx++]=(myId>>8)&0xFF;pkt[idx++]=myId&0xFF;
  pkt[idx++]=(destId>>24)&0xFF;pkt[idx++]=(destId>>16)&0xFF;pkt[idx++]=(destId>>8)&0xFF;pkt[idx++]=destId&0xFF;
  uint32_t pid;mbedtls_ctr_drbg_random(&ctrDrbg,(uint8_t*)&pid,4);
  pkt[idx++]=(pid>>24)&0xFF;pkt[idx++]=(pid>>16)&0xFF;pkt[idx++]=(pid>>8)&0xFF;pkt[idx++]=pid&0xFF;
  pkt[idx++]=3;pkt[idx++]=64;
  memcpy(&pkt[idx],iv,AES_IV_SIZE);idx+=AES_IV_SIZE;
  memcpy(&pkt[idx],ct,64);idx+=64;
  radio.transmit(pkt,idx);radio.startReceive();
}
void handleRoomInvite(uint8_t* buf,int len){
  if(len<32)return;
  uint32_t src=((uint32_t)buf[1]<<24)|((uint32_t)buf[2]<<16)|((uint32_t)buf[3]<<8)|(uint32_t)buf[4];
  if(!isContact(src))return;
  uint8_t sk[AES_KEY_SIZE];if(!getSharedKey(src,sk))return;
  int cl=buf[14];if(len<15+AES_IV_SIZE+cl)return;
  uint8_t* iv=&buf[15];uint8_t* ct=&buf[15+AES_IV_SIZE];
  uint8_t pt[256];int pl=decryptAES256(sk,iv,ct,cl,pt);if(pl<64)return;
  uint32_t rid=((uint32_t)pt[0]<<24)|((uint32_t)pt[1]<<16)|((uint32_t)pt[2]<<8)|(uint32_t)pt[3];
  if(rid==0)return;
  uint8_t rkey[AES_KEY_SIZE];memcpy(rkey,&pt[4],AES_KEY_SIZE);
  char rname[ROOM_NAME_LEN];memset(rname,0,ROOM_NAME_LEN);memcpy(rname,&pt[36],ROOM_NAME_LEN-1);
  if(addRoom(rid,rkey,rname)){
    addRoomMember(rid,getMyNodeId());addRoomMember(rid,src);
    char nm[48];snprintf(nm,sizeof(nm),"[Added to room: %s]",rname);
    storeMessage(src,false,false,nm,0,rid);
    Serial.printf("[Rooms] Invited to %08X\n",rid);
  }
}
void sendAck(uint32_t destId,uint32_t pid,uint8_t type){
  if(!loraReady)return;
  uint32_t myId=getMyNodeId();
  uint8_t pkt[14];
  pkt[0]=type;
  pkt[1]=(myId>>24)&0xFF;pkt[2]=(myId>>16)&0xFF;pkt[3]=(myId>>8)&0xFF;pkt[4]=myId&0xFF;
  pkt[5]=(destId>>24)&0xFF;pkt[6]=(destId>>16)&0xFF;pkt[7]=(destId>>8)&0xFF;pkt[8]=destId&0xFF;
  pkt[9]=(pid>>24)&0xFF;pkt[10]=(pid>>16)&0xFF;pkt[11]=(pid>>8)&0xFF;pkt[12]=pid&0xFF;
  pkt[13]=3;
  radio.transmit(pkt,14);radio.startReceive();
}
void handleAck(uint8_t* buf,int len,uint8_t type){
  if(len<13)return;
  uint32_t src=((uint32_t)buf[1]<<24)|((uint32_t)buf[2]<<16)|((uint32_t)buf[3]<<8)|(uint32_t)buf[4];
  uint32_t dst=((uint32_t)buf[5]<<24)|((uint32_t)buf[6]<<16)|((uint32_t)buf[7]<<8)|(uint32_t)buf[8];
  uint32_t pid=((uint32_t)buf[9]<<24)|((uint32_t)buf[10]<<16)|((uint32_t)buf[11]<<8)|(uint32_t)buf[12];
  Serial.printf("[ACK] rx %s from %08X pid %08X\n",type==PKT_TYPE_READ?"READ":"DELIVERED",src,pid);
  if(dst!=getMyNodeId())return;
  for(int i=0;i<MAX_MESSAGES;i++){
    ChatMessage& m=messageStore[i];
    if(!(m.isMe&&m.isPrivate&&m.toNode==src))continue;
    if(type==PKT_TYPE_READ){if(m.status<2){m.status=2;messagesDirty=true;}}
    else if(m.msgId==pid){if(m.status<1){m.status=1;messagesDirty=true;}}
  }
}

// =============================================================
//  SECTION 17 — KEY REVOCATION
// =============================================================
void sendRevocation() {
  if(!loraReady||!cryptoReady)return;
  uint32_t myId=getMyNodeId();
  uint8_t pkt[10];
  pkt[0]=PKT_TYPE_REVOKE;
  pkt[1]=(myId>>24)&0xFF;pkt[2]=(myId>>16)&0xFF;pkt[3]=(myId>>8)&0xFF;pkt[4]=myId&0xFF;
  pkt[5]=myPublicKey[0];pkt[6]=myPublicKey[1];pkt[7]=myPublicKey[2];pkt[8]=myPublicKey[3];
  pkt[9]=0xFF;
  radio.startTransmit(pkt,sizeof(pkt));
  Serial.println("[Security] Revocation broadcast sent");
}
void handleRevocation(uint8_t* buf,int len){
  if(len<9)return;
  uint32_t revokedId=((uint32_t)buf[1]<<24)|((uint32_t)buf[2]<<16)|((uint32_t)buf[3]<<8)|(uint32_t)buf[4];
  if(isContact(revokedId)){
    Serial.printf("[Security] Revocation received for contact %08X\n",revokedId);
    removeContact(revokedId);
    char msg[48];sprintf(msg,"[Contact %08X revoked their key]",revokedId);
    storeMessage(revokedId,false,false,msg);
  }
}

// =============================================================
//  SECTION 18 — WEB SERVER
// =============================================================
void setupWebServer(){
  const char* hdrs[]={"Cookie","Content-Type"};
  server.collectHeaders(hdrs,2);
  server.on("/",HTTP_GET,[](){
    server.sendHeader("Cache-Control","no-store, no-cache, must-revalidate");
    touchSession();
    if(!checkSessionCookie()){
      if(!isPinSet()){
        String html=F("<!DOCTYPE html><html><head>"
          "<meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
          "<title>PLSChat Setup</title>"
          "<style>body{font-family:system-ui,sans-serif;background:#0d0d1a;color:#e0e0f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;}"
          ".box{background:#1a1a2e;padding:32px;border-radius:16px;max-width:360px;width:90%;text-align:center;}"
          "h2{color:#a855f7;margin-bottom:8px;}p{color:#94a3b8;font-size:14px;margin-bottom:20px;}"
          "input{width:100%;padding:12px;margin-bottom:12px;border:1px solid #2a2a40;border-radius:8px;background:#12121f;color:#fff;font-size:18px;text-align:center;letter-spacing:6px;box-sizing:border-box;}"
          ".btn{width:100%;padding:12px;background:linear-gradient(135deg,#a855f7,#3b82f6);color:white;border:none;border-radius:8px;font-size:16px;cursor:pointer;font-weight:600;}"
          ".hint{font-size:12px;color:#606080;margin-top:12px;}"
          "</style></head><body>"
          "<div class='box'>"
          "<h2>PLSChat Setup</h2>"
          "<p>Set a PIN to protect your device.<br>You will need this every time you access the web UI.</p>"
          "<form method='POST' action='/setpin'>"
          "<input type='password' name='pin' placeholder='PIN' maxlength='6' minlength='4' inputmode='numeric' pattern='[0-9]{4,6}' required autofocus>"
          "<input type='password' name='pin2' placeholder='Confirm PIN' maxlength='6' minlength='4' inputmode='numeric' pattern='[0-9]{4,6}' required>"
          "<button class='btn' type='submit'>Set PIN &amp; Unlock</button>"
          "</form>"
          "<p class='hint'>4-6 digits. Write it down.</p>"
          "</div></body></html>");
        server.send(200,"text/html",html);
      } else {
        bool wrong=server.hasArg("wrong");
        bool locked=server.hasArg("locked");
        String html=F("<!DOCTYPE html><html><head>"
          "<meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
          "<title>PLSChat Unlock</title>"
          "<style>body{font-family:system-ui,sans-serif;background:#0d0d1a;color:#e0e0f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;}"
          ".box{background:#1a1a2e;padding:32px;border-radius:16px;max-width:360px;width:90%;text-align:center;}"
          "h2{color:#a855f7;margin-bottom:8px;}p{color:#94a3b8;font-size:14px;margin-bottom:20px;}"
          "input{width:100%;padding:12px;margin-bottom:16px;border:1px solid #2a2a40;border-radius:8px;background:#12121f;color:#fff;font-size:24px;text-align:center;letter-spacing:8px;box-sizing:border-box;}"
          ".btn{width:100%;padding:12px;background:linear-gradient(135deg,#a855f7,#3b82f6);color:white;border:none;border-radius:8px;font-size:16px;cursor:pointer;font-weight:600;}"
          ".err{color:#f08080;font-size:13px;margin-bottom:12px;}"
          ".hint{font-size:12px;color:#606080;margin-top:12px;}"
          "</style></head><body>"
          "<div class='box'>"
          "<h2>&#128274; PLSChat</h2>");
        if(locked) html+=F("<p class='err'>Too many attempts. Try again later.</p>");
        else if(wrong) html+=F("<p class='err'>Wrong PIN. Try again.</p>");
        else html+=F("<p>Enter your PIN to access PLSChat</p>");
        html+=F("<form method='POST' action='/unlock'>"
          "<input type='password' name='pin' placeholder='PIN' maxlength='6' minlength='4' inputmode='numeric' pattern='[0-9]{4,6}' required autofocus>"
          "<button class='btn' type='submit'>Unlock</button>"
          "</form>"
          "<p class='hint'>Forgot your PIN? Hold the BOOT button while powering on for hardware reset.</p>"
          "</div></body></html>");
        server.send(200,"text/html",html);
      }
      return;
    }

    String mac=WiFi.macAddress();
    String licClass=isLicensed?"ok":"no";
    String licTxt=isLicensed?"&#10003; Licensed":"&#10007; Unlicensed";
    String wifiChk=wifiEnabled?"checked":"";
    String bleChk=bleEnabled?"checked":"";
    String pairCode=generatePairingCode();
    String pairPayload=getPairingPayload();
    char nid[12];sprintf(nid,"%08X",getMyNodeId());

    unsigned long _pgT0=millis();
    server.setContentLength(CONTENT_LENGTH_UNKNOWN);
    server.send(200,"text/html","");

    if(server.hasArg("saved"))   server.sendContent("<div class='msg ok'>&#10003; Settings saved.</div>");
    if(server.hasArg("licok"))   server.sendContent("<div class='msg ok'>&#10003; Licence accepted.</div>");
    if(server.hasArg("licfail")) server.sendContent("<div class='msg err'>&#10007; Licence invalid.</div>");
    if(server.hasArg("paired"))  server.sendContent("<div class='msg ok'>&#10003; Contact paired!</div>");
    if(server.hasArg("pairfail"))server.sendContent("<div class='msg err'>&#10007; Pairing failed.</div>");
    if(server.hasArg("removed")) server.sendContent("<div class='msg ok'>Contact removed.</div>");
    if(server.hasArg("pinok"))   server.sendContent("<div class='msg ok'>&#10003; PIN changed.</div>");
    if(server.hasArg("pinfail")) server.sendContent("<div class='msg err'>&#10007; PIN change failed.</div>");

    String html=F("<!DOCTYPE html><html><head>"
      "<meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
      "<title>PLSChat " PLSCHAT_VERSION "</title>"
      "<style>"
      ":root{--bg:#f0f0f0;--card:#fff;--brd:#e0e0e0;--txt:#111;--txt2:#555;--txt3:#888;"
      "--inp:#fafafa;--stat:#f5f5f5;--rowb:#efefef;--hdr:#1a1a2e;--hdrtxt:#fff;"
      "--btn:#1a1a2e;--btntxt:#fff;--ok-bg:#e8f8f0;--ok-txt:#0a7a3e;"
      "--err-bg:#fee8e8;--err-txt:#c00;--hint:#999;}"
      "body.dark{--bg:#0d0d1a;--card:#1a1a2e;--brd:#2a2a40;--txt:#e0e0f0;--txt2:#a0a0c0;"
      "--txt3:#606080;--inp:#12121f;--stat:#12121f;--rowb:#222235;"
      "--hdr:#07070f;--hdrtxt:#e0e0f0;--btn:#00d4aa;--btntxt:#0d0d1a;"
      "--ok-bg:#0a2a1a;--ok-txt:#4de8a0;"
      "--err-bg:#2a0a0a;--err-txt:#f08080;--hint:#505068;}"
      "*{box-sizing:border-box;margin:0;padding:0}"
      "body{font-family:system-ui,sans-serif;background:var(--bg);padding:16px;color:var(--txt)}"
      ".wrap{max-width:500px;margin:0 auto}"
      ".hdr{background:var(--hdr);padding:12px 16px;border-radius:10px 10px 0 0;"
        "display:flex;justify-content:space-between;align-items:center}"
      ".hdr-title{font-size:15px;font-weight:600;color:var(--hdrtxt);display:flex;align-items:center;gap:8px}"
      ".hdr-title::before{content:'';width:8px;height:8px;border-radius:50%;background:#00d4aa;display:inline-block}"
      ".card{background:var(--card);border:1px solid var(--brd);padding:16px;margin-bottom:2px}"
      ".card:last-of-type{border-radius:0 0 10px 10px}"
      ".lbl{font-size:11px;font-weight:600;color:var(--txt3);letter-spacing:.8px;text-transform:uppercase;margin-bottom:10px}"
      ".stat-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px}"
      ".stat{background:var(--stat);border-radius:6px;padding:8px 10px}"
      ".stat .val{font-size:15px;font-weight:600;color:var(--txt)}"
      ".stat .desc{font-size:11px;color:var(--txt3);margin-top:2px}"
      ".pill{font-size:11px;padding:3px 9px;border-radius:20px;font-weight:600}"
      ".pill.ok{background:var(--ok-bg);color:var(--ok-txt)}"
      ".pill.no{background:var(--err-bg);color:var(--err-txt)}"
      ".row{display:flex;justify-content:space-between;align-items:center;padding:9px 0;border-bottom:1px solid var(--rowb)}"
      ".row:last-child{border-bottom:none}.row label{font-size:14px;color:var(--txt)}"
      ".btn{width:100%;padding:11px;background:var(--btn);color:var(--btntxt);border:none;border-radius:6px;font-size:14px;cursor:pointer;font-weight:500}"
      ".btn-sm{padding:7px 14px;background:var(--btn);color:var(--btntxt);border:none;border-radius:6px;font-size:13px;cursor:pointer;font-weight:500}"
      ".btn-warn{background:#c00;color:#fff}"
      ".field{margin-bottom:12px}.field label{display:block;font-size:13px;color:var(--txt2);margin-bottom:4px}"
      ".field input{width:100%;padding:8px 10px;border:1px solid var(--brd);border-radius:6px;font-size:14px;background:var(--inp);color:var(--txt)}"
      ".hint{font-size:11px;color:var(--hint);margin-top:5px;line-height:1.4}"
      ".msg{padding:10px 14px;border-radius:6px;font-size:13px;margin-bottom:10px}"
      ".msg.ok{background:var(--ok-bg);color:var(--ok-txt)}.msg.err{background:var(--err-bg);color:var(--err-txt)}"
      ".nav-outer{position:relative;border-bottom:1px solid var(--brd);margin:6px 0 14px}"
      ".nav-scroll{overflow-x:auto;scrollbar-width:none}"
      ".nav-inner{display:flex;min-width:max-content}"
      ".nav-btn{padding:10px 16px;font-size:13px;font-weight:600;color:var(--txt3);background:transparent;border:none;border-bottom:2px solid transparent;cursor:pointer;white-space:nowrap}"
      ".nav-btn.active{color:#a855f7;border-bottom-color:#a855f7}"
      ".nbadge{display:inline-flex;align-items:center;justify-content:center;background:#E24B4A;color:#fff;border-radius:8px;font-size:9px;font-weight:700;min-width:14px;height:14px;padding:0 3px;margin-left:4px;vertical-align:middle}"
      ".section{display:none}.section.active{display:block}"
      ".chat-tabs{display:flex;gap:4px;margin-bottom:8px;flex-wrap:wrap}"
      ".chat-tab{padding:6px 12px;border-radius:20px;font-size:12px;font-weight:600;cursor:pointer;border:1px solid var(--brd);background:var(--inp);color:var(--txt3);transition:all .2s;white-space:nowrap}"
      ".chat-tab.active{background:linear-gradient(135deg,#a855f7,#3b82f6);color:#fff;border-color:transparent}"
      ".chat-tab.unread{border-color:#a855f7;color:#a855f7}"
      ".chat-tab .tabcount{display:inline-flex;align-items:center;justify-content:center;min-width:16px;height:16px;padding:0 4px;margin-left:5px;border-radius:8px;background:#ff3b6b;color:#fff;font-size:10px;font-weight:700;vertical-align:middle}"
      ".chat-box{background:var(--stat);border-radius:8px;padding:10px;min-height:160px;max-height:280px;overflow-y:auto;font-size:13px;margin-top:4px}"
      ".chat-msg{padding:8px 12px;border-radius:12px;margin-bottom:6px;max-width:78%;word-break:break-word;line-height:1.45;font-size:13px}"
      ".chat-msg.me{background:linear-gradient(135deg,#a855f7,#7c3aed);color:#fff;margin-left:auto;text-align:right;border-bottom-right-radius:3px}"
      ".chat-msg.pub{background:var(--rowb);color:var(--txt);border-bottom-left-radius:3px}"
      ".chat-msg.priv{background:rgba(34,211,238,0.12);color:#67e8f9;border-bottom-left-radius:3px;border-left:3px solid #22d3ee}"
      ".chat-from{font-size:10px;opacity:.65;margin-bottom:3px;font-weight:700}"
      ".send-wrap{margin-top:8px}"
      ".toggle{position:relative;display:inline-block;width:44px;height:24px;flex-shrink:0}"
      ".toggle input{opacity:0;width:0;height:0}"
      ".slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background:#334155;border-radius:24px;transition:.3s}"
      ".slider:before{position:absolute;content:'';height:18px;width:18px;left:3px;bottom:3px;background:white;border-radius:50%;transition:.3s}"
      "input:checked+.slider{background:linear-gradient(135deg,#a855f7,#3b82f6)}"
      "input:checked+.slider:before{transform:translateX(20px)}"
      ".send-row{display:flex;gap:6px;align-items:center}"
      ".send-row input{flex:1;padding:9px 12px;border:1px solid var(--brd);border-radius:20px;font-size:14px;background:var(--inp);color:var(--txt)}"
      ".send-row .btn-send{padding:9px 18px;background:linear-gradient(135deg,#a855f7,#3b82f6);color:#fff;border:none;border-radius:20px;font-size:14px;font-weight:600;cursor:pointer}"
      ".contact-row{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--rowb)}"
      ".tog-wrap{display:flex;align-items:center;gap:7px;cursor:pointer;user-select:none}"
      ".tog-track{width:38px;height:21px;background:#444;border-radius:11px;position:relative;transition:background .2s}"
      ".tog-track::after{content:'';position:absolute;width:17px;height:17px;background:#fff;border-radius:50%;top:2px;left:2px;transition:left .2s}"
      ".tog-wrap input:checked+.tog-track{background:#00d4aa}"
      ".tog-wrap input:checked+.tog-track::after{left:19px}"
      "a{color:var(--txt3);font-size:12px}"
      "</style></head><body><div class='wrap'>");
    server.sendContent(html);html="";

    html+="<div class='hdr'><div class='hdr-title'>PLSChat " PLSCHAT_VERSION "</div>"
          "<div style='display:flex;align-items:center;gap:10px'>"
          "<button onclick='lockNow()' style='padding:7px 14px;background:#c00;color:#fff;border:none;border-radius:8px;font-size:13px;font-weight:700;cursor:pointer'>&#128274; Lock</button>"
          "<label class='tog-wrap'>"
          "<span id='modeIcon' style='font-size:16px'>&#9728;</span>"
          "<input type='checkbox' id='dkTog' style='display:none'>"
          "<div class='tog-track'></div>"
          "<span id='modeLabel' style='font-size:11px;color:var(--txt3);min-width:28px'>Light</span>"
          "</label></div></div>";
    html+="<div class='nav-outer'><div class='nav-scroll'><div class='nav-inner'>"
          "<div class='nav-btn' id='nb-settings' onclick=\"goTab('settings')\">Settings</div>"
          "<div class='nav-btn' id='nb-status' onclick=\"goTab('status')\">Status</div>"
          "<div class='nav-btn active' id='nb-chat' onclick=\"goTab('chat')\">Chat<span class='nbadge' id='navBadgeChat' style='display:none'></span></div>"
          "<div class='nav-btn' id='nb-rooms' onclick=\"goTab('rooms')\">Rooms</div>"
          "<div class='nav-btn' id='nb-contacts' onclick=\"goTab('contacts')\">Contacts</div>"
          "</div></div></div>";

    // STATUS TAB
    html+="<div class='section' id='sec-status'>";
    html+="<div class='card'><div class='lbl'>Device status</div>"
          "<div class='row'><span style='font-size:13px;color:var(--txt2)'>Licence</span>"
          "<span class='pill "+licClass+"'>"+licTxt+"</span></div>"
          "<div class='row'><span style='font-size:13px;color:var(--txt2)'>Tier</span>"
          "<span style='font-family:monospace;font-weight:700;color:#a855f7'>"+String(licState.valid?licState.tier:"none")+"</span></div>"
          "<div class='row'><span style='font-size:13px;color:var(--txt2)'>Days Left</span>"
          "<span style='font-family:monospace;font-weight:700;color:#a855f7'>"+getDaysLeftString()+"</span></div>"
          "<div class='row'><span style='font-size:13px;color:var(--txt2)'>Node ID</span>"
          "<span style='font-family:monospace;font-weight:700;color:#a855f7'>"+String(nid)+"</span></div>"
          "<div class='row'><span style='font-size:13px;color:var(--txt2)'>MAC</span>"
          "<span style='font-size:11px;font-family:monospace'>"+mac+"</span></div>"
          "<div class='stat-grid'>"
          "<div class='stat'><div class='val'>"+String(batPct)+"%</div><div class='desc'>Battery"+String(isCharging?" (charging)":"")+"</div></div>"
          "<div class='stat'><div class='val' id='loraVal'>--</div><div class='desc'>LoRa signal</div></div>"
          "<div class='stat'><div class='val'>"+getUptimeString()+"</div><div class='desc'>Uptime</div></div>"
          "<div class='stat'><div class='val' id='cntVal'>"+String(countContacts())+"</div><div class='desc'>Contacts</div></div>"
          "</div></div>";
    html+="<div class='card'><div class='lbl'>LoRa signal</div>"
          "<div style='display:flex;align-items:center;gap:12px;margin-bottom:8px'>"
          "<div id='sigBig' style='font-size:32px;font-weight:700;min-width:90px'>--</div>"
          "<div><div id='sigQual' style='font-size:14px;font-weight:600;color:var(--txt2)'>Waiting...</div>"
          "<div id='sigSub' style='font-size:12px;color:var(--txt3)'></div></div></div>"
          "<div style='background:var(--stat);border-radius:6px;height:10px;overflow:hidden'>"
          "<div id='sigBar' style='height:100%;width:0%;background:#00d4aa;transition:width .5s;border-radius:6px'></div>"
          "</div></div>";
    html+="</div>"; // /sec-status
    server.sendContent(html);html="";

    // CHAT TAB
    html+="<div class='section active' id='sec-chat'>";
    html+="<div class='card'><div class='lbl'>Messages</div>"
          "<div class='chat-tabs'>"
          "<div class='chat-tab active' id='tab_pub' onclick=\"switchTab('pub')\">&#127760; Public</div>";
    int contactCount=0;
    for(int i=0;i<MAX_CONTACTS;i++){
      if(!contacts[i].valid)continue;
      char oid[12];sprintf(oid,"%08X",contacts[i].nodeId);
      html+="<div class='chat-tab' id='tab_"+String(oid)+"' data-nm='"+String(contacts[i].name)+"' onclick=\"switchTab('"+String(oid)+"')\">&#128274; "+String(contacts[i].name)+"</div>";
      contactCount++;
    }
    for(int i=0;i<MAX_ROOMS;i++){
      if(!rooms[i].valid)continue;
      char rtid[12];sprintf(rtid,"%08X",rooms[i].roomId);
      html+="<div class='chat-tab' id='tab_room_"+String(rtid)+"' data-nm='"+String(rooms[i].name)+"' onclick=\"switchTab('room_"+String(rtid)+"')\">&#128101; "+String(rooms[i].name)+"</div>";
    }
    html+="</div>"
          "<div class='chat-box' id='chatBox'></div>"
          "<div class='send-wrap'>"
          "<div id='chatToLabel' style='font-size:11px;color:var(--txt3);margin-bottom:4px'>&#127760; Broadcasting to public channel</div>"
          "<div class='send-row'>"
          "<input type='text' id='msgInp' placeholder='Message...' maxlength='400' autocomplete='off' oninput='updateCharCount()'>"
          "<button class='btn-send' onclick='sendMsg()'>&#10148;</button>"
          "</div>"
          "<div id='charCount' style='font-size:10px;color:var(--txt3);text-align:right;margin-top:3px'></div>"
          "<div id='licHint' style='display:none;font-size:10px;color:#ff9800;text-align:center;margin-top:4px'></div>"
          "</div>"
          "<input type='hidden' id='chatTo' value='pub'>"
          "</div>";
    html+="</div>"; // /sec-chat
    server.sendContent(html);html="";

    // CONTACTS TAB
    html+="<div class='section' id='sec-contacts'>";
    const char* avCols[]={"background:#7c3aed20;color:#7c3aed","background:#0f6e5620;color:#0f6e56","background:#9a3c1d20;color:#9a3c1d","background:#185fa520;color:#185fa5"};
    html+="<div class='card'>";
    html+="<div style='display:flex;align-items:center;justify-content:space-between;padding:14px 14px 10px'>"
          "<div style='font-size:15px;font-weight:700;color:var(--txt)'>Contacts ("+String(countContacts())+")</div>"
          "<button onclick='toggleAddContact()' style='padding:7px 14px;background:#7c3aed;color:#fff;border:none;border-radius:8px;font-size:13px;font-weight:700;cursor:pointer'>+ Add</button>"
          "</div>";
    if(countContacts()==0){
      html+="<div style='padding:20px;text-align:center;color:var(--txt3);font-size:13px;border-top:0.5px solid var(--brd)'>No contacts yet. Tap <b>+ Add</b> to pair.</div>";
    } else {
      int avI=0;
      for(int i=0;i<MAX_CONTACTS;i++){
        if(!contacts[i].valid)continue;
        char oid[12];sprintf(oid,"%08X",contacts[i].nodeId);
        String cn=String(contacts[i].name);
        html+="<div class='cRow' data-search='"+cn+" "+String(oid)+"' style='display:flex;align-items:center;gap:10px;padding:10px 14px;border-top:0.5px solid var(--brd)'>"
              "<div style='width:38px;height:38px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;flex-shrink:0;"+String(avCols[avI%4])+"'>"+String((char)toupper(cn[0]))+"</div>"
              "<div style='flex:1;min-width:0;cursor:pointer' onclick='switchToPrivate(\""+String(oid)+"\")'>"
              "<div style='font-size:14px;font-weight:600;color:var(--txt)'>"+cn+(contacts[i].verified?" <span style='color:#1f9d6b;font-size:13px;font-weight:700' title='Identity verified'>&#10003;</span>":"")+"</div>"
              "<div style='font-size:11px;font-family:monospace;color:var(--txt3)'>"+String(oid)+"</div>"
              "</div>"
              "<div style='display:flex;gap:6px;align-items:center'>"
              "<button onclick='openVerify(\""+String(oid)+"\",\""+cn+"\")' title='Verify identity' style='width:32px;height:32px;border-radius:50%;background:var(--inp);color:"+String(contacts[i].verified?"#1f9d6b":"#e2494a")+";border:1px solid "+String(contacts[i].verified?"#1f9d6b":"#e2494a")+";cursor:pointer;font-size:17px;font-weight:700;line-height:1'>&#10003;</button>"
              "<button onclick='switchToPrivate(\""+String(oid)+"\")' id='cbtn_"+String(oid)+"' style='min-width:32px;height:32px;padding:0 6px;border-radius:16px;background:#1f9d6b;color:#fff;border:none;cursor:pointer'>&#128172;</button>"
              "<button onclick='editName(\""+String(oid)+"\")' style='width:32px;height:32px;border-radius:50%;background:var(--inp);color:var(--txt2);border:0.5px solid var(--brd);cursor:pointer'>&#9998;</button>"
              "<button onclick='removeContact(\""+String(oid)+"\")' style='font-size:11px;padding:4px 8px;border:0.5px solid #c00;color:#c00;background:transparent;border-radius:6px;cursor:pointer'>Remove</button>"
              "</div></div>";
        avI++;
      }
    }
    html+="<div id='addContactPanel' style='display:none;border-top:0.5px solid var(--brd);padding:12px 14px'>"          "<div style='font-size:11px;font-weight:700;color:var(--txt3);text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px'>Your Identity</div>"          "<div style='background:var(--stat);border-radius:8px;padding:10px;margin-bottom:8px'>"          "<div style='font-size:11px;color:var(--txt3);margin-bottom:4px'>Short code (safe to share)</div>"          "<div style='display:flex;align-items:center;gap:8px'>"          "<div style='font-family:monospace;font-size:22px;font-weight:700;color:#a855f7;flex:1'>PL-"+pairCode+"</div>"          "<button onclick='copyShortCode()' style='padding:5px 12px;background:#7c3aed;color:#fff;border:none;border-radius:6px;font-size:12px;font-weight:700;cursor:pointer'><span id='copyShortBtn'>&#128203; Copy</span></button>"          "</div></div>"          "<div style='background:var(--stat);border-radius:8px;padding:10px;margin-bottom:14px'>"          "<div style='font-size:11px;color:var(--txt3);margin-bottom:4px'>Full pairing key</div>"          "<div style='font-family:monospace;font-size:11px;word-break:break-all;background:var(--rowb);padding:8px;border-radius:6px;margin-bottom:6px' id='pairPayload'>"+pairPayload+"</div>"          "<button onclick='copyPair()' style='width:100%;padding:7px;background:#7c3aed;color:#fff;border:none;border-radius:6px;font-size:12px;font-weight:700;cursor:pointer'><span id='copyPairBtn'>&#128203; Copy full key</span></button>"          "</div>"          "<div style='font-size:11px;font-weight:700;color:var(--txt3);text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px'>Add a Contact</div>"          "<div class='field'><label>Their short code</label>"          "<input type='text' id='loraShortCode' placeholder='PL-XXXXXXXX' maxlength='11' style='text-transform:uppercase;font-family:monospace'></div>"          "<div class='field'><label>Name for this contact</label>"          "<input type='text' id='loraPairName' placeholder='e.g. Bob' maxlength='15'></div>"          "<button class='btn' onclick='sendLoraRequest()' id='loraSendBtn'>&#128225; Send LoRa Request</button>"          "<div id='loraReqResult' style='font-size:13px;margin-top:10px;line-height:1.5'></div>"          "</div>"          "</div>";    html+="</div>"; // /sec-contacts
    server.sendContent(html);html="";

    // ROOMS TAB
    html+="<div class='section' id='sec-rooms'>";
    if(!isLicensed){
      html+="<div class='card' style='text-align:center;padding:30px 20px'>"
            "<div style='font-size:32px;margin-bottom:10px'>&#128272;</div>"
            "<div style='font-size:15px;font-weight:700;color:var(--txt);margin-bottom:6px'>Rooms require a licence</div>"
            "<div style='font-size:13px;color:var(--txt3);margin-bottom:16px'>Encrypted group rooms are a premium feature.</div>"
            "<a href='/settings' style='display:inline-block;padding:10px 24px;background:#7c3aed;color:#fff;border-radius:10px;font-size:13px;font-weight:700;text-decoration:none'>Enter Licence Key</a>"
            "</div>";
    } else {
    html+="<div class='card'>";
    html+="<div style='display:flex;align-items:center;justify-content:space-between;padding:14px 14px 10px'>"
          "<div style='font-size:15px;font-weight:700;color:var(--txt)'>Rooms</div>"
          "<button onclick='toggleCreateRoom()' style='padding:7px 14px;background:#0f6e56;color:#fff;border:none;border-radius:8px;font-size:13px;font-weight:700;cursor:pointer'>+ Create</button>"
          "</div>";
    {int roomN=0;
    for(int i=0;i<MAX_ROOMS;i++){
      if(!rooms[i].valid)continue;roomN++;
      char rid9[12];sprintf(rid9,"%08X",rooms[i].roomId);
      String privBadge=rooms[i].isPrivate?"<span style='font-size:9px;padding:1px 6px;background:rgba(124,58,237,0.15);color:#a855f7;border-radius:8px;margin-left:6px'>&#128274; Private</span>":"";
      html+="<div style='display:flex;align-items:center;gap:10px;padding:12px 14px;border-bottom:0.5px solid var(--brd)' data-rid='"+String(rid9)+"'>"
            "<div style='width:36px;height:36px;border-radius:10px;background:linear-gradient(135deg,#0f6e56,#3b82f6);display:flex;align-items:center;justify-content:center;font-size:16px'>&#128101;</div>"
            "<div style='flex:1;min-width:0;cursor:pointer' onclick='openRoom(this.parentNode.dataset.rid)'>"
            "<div style='font-size:14px;font-weight:600;color:var(--txt)'>"+String(rooms[i].name)+privBadge+"</div>"
            "<div style='font-size:11px;color:var(--txt3)'>"+String(rooms[i].memberCount>0?roomMembersStr(i):"Tap to open chat")+"</div></div>"
            "<button onclick='openRoom(this.parentNode.dataset.rid)' title='Open' style='min-width:32px;height:32px;padding:0 6px;border-radius:16px;background:#1f9d6b;color:#fff;border:none;cursor:pointer;font-size:14px'>&#128172;</button>"
            "<button onclick='renameRoom(this.parentNode.dataset.rid)' title='Rename' style='min-width:32px;height:32px;padding:0;border-radius:16px;background:var(--inp);color:var(--txt3);border:0.5px solid var(--brd);cursor:pointer;font-size:13px'>&#9998;</button>"
            "<button onclick='showAddMembers(this.parentNode.dataset.rid)' title='Add members' style='min-width:32px;height:32px;padding:0;border-radius:16px;background:var(--inp);color:#1f9d6b;border:0.5px solid var(--brd);cursor:pointer;font-size:18px;line-height:1'>&#43;</button>"
            "<button onclick='leaveRoom(this.parentNode.dataset.rid)' title='Leave' style='min-width:32px;height:32px;padding:0;border-radius:16px;background:var(--inp);color:#E24B4A;border:0.5px solid var(--brd);cursor:pointer;font-size:15px'>&#10005;</button>"
            "</div>";
    }
    if(roomN==0)html+="<div style='padding:20px;text-align:center;color:var(--txt3);font-size:13px'>No rooms yet. Tap <b>+ Create</b> to set one up.</div>";}
    // Add-members panel
    html+="<div id='addMemberPanel' data-rid='' style='display:none;border-top:0.5px solid var(--brd);padding:12px 14px'>"
          "<div style='font-size:11px;font-weight:700;color:var(--txt3);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:10px'>Add members to <span id='addRoomName'>room</span></div>"
          "<div style='display:flex;flex-wrap:wrap;gap:10px;margin-bottom:10px'>";
    bool anyAdd=false;
    for(int i=0;i<MAX_CONTACTS;i++){
      if(!contacts[i].valid)continue;anyAdd=true;
      char oid4[12];sprintf(oid4,"%08X",contacts[i].nodeId);
      char initial2[2]={contacts[i].name[0],0};
      html+="<label style='display:flex;flex-direction:column;align-items:center;gap:4px;cursor:pointer;min-width:52px'>"
            "<div style='position:relative;width:44px;height:44px'>"
            "<div style='width:44px;height:44px;border-radius:50%;background:linear-gradient(135deg,#1f9d6b,#3b82f6);display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:700;color:#fff'>"+String(initial2)+"</div>"
            "<input type='checkbox' value='"+String(oid4)+"' name='addMember' style='position:absolute;bottom:0;right:0;width:18px;height:18px;accent-color:#1f9d6b'>"
            "</div>"
            "<div style='font-size:10px;color:var(--txt3);text-align:center;max-width:52px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>"+String(contacts[i].name)+"</div>"
            "</label>";
    }
    if(!anyAdd)html+="<div style='font-size:12px;color:var(--txt3)'>No contacts to add</div>";
    html+="</div>"
          "<button class='btn' onclick='submitAddMembers()' style='width:100%;margin-top:4px'>Add selected</button>"
          "<div id='addResult' style='font-size:12px;margin-top:8px'></div>"
          "</div>";
    // Create room panel
    html+="<div id='createRoomPanel' style='display:none;border-top:0.5px solid var(--brd);padding:14px'>"
          "<div style='font-size:10px;font-weight:700;color:var(--txt3);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px'>New Room</div>"
          "<div class='field'><label>Room name</label><input type='text' id='rName' placeholder='e.g. Base camp' maxlength='20'></div>"
          "<div style='display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px'>"
          "<div class='field' style='margin:0'><label>Max stored messages</label><input type='number' id='rMaxMsgs' value='50' min='10' max='200' step='10'></div>"
          "<div class='field' style='margin:0'><label>Max members</label><input type='number' id='rMaxMembers' value='8' min='2' max='12'></div>"
          "</div>"
          "<div class='toggle-row' style='margin-bottom:12px;display:flex;align-items:center;justify-content:space-between;gap:12px'>"
          "<div><div style='font-size:13px;font-weight:600;color:var(--txt)'>Private room</div><div style='font-size:11px;color:var(--txt3)'>Invite key required to join</div></div>"
          "<label class='toggle'><input type='checkbox' id='rPrivate' checked><span class='slider'></span></label>"
          "</div>"
          "<div class='field'><label>Add members from contacts</label>"
          "<div style='display:flex;flex-wrap:wrap;gap:10px;margin-top:8px'>";
    bool hasContacts=false;
    for(int i=0;i<MAX_CONTACTS;i++){
      if(!contacts[i].valid)continue;hasContacts=true;
      char oid3[12];sprintf(oid3,"%08X",contacts[i].nodeId);
      char initial[2]={contacts[i].name[0],0};
      html+="<label style='display:flex;flex-direction:column;align-items:center;gap:4px;cursor:pointer;min-width:52px'>"
            "<div style='position:relative;width:44px;height:44px'>"
            "<div style='width:44px;height:44px;border-radius:50%;background:linear-gradient(135deg,#1f9d6b,#3b82f6);display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:700;color:#fff'>"+String(initial)+"</div>"
            "<input type='checkbox' value='"+String(oid3)+"' name='roomMember' style='position:absolute;bottom:0;right:0;width:18px;height:18px;accent-color:#1f9d6b'>"
            "</div>"
            "<div style='font-size:10px;color:var(--txt3);text-align:center;max-width:52px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>"+String(contacts[i].name)+"</div>"
            "</label>";
    }
    if(!hasContacts)html+="<div style='font-size:12px;color:var(--txt3)'>No contacts yet</div>";
    html+="</div></div>"
          "<button class='btn' onclick='createRoom()' style='width:100%;margin-top:8px'>&#128101; Create room</button>"
          "<div id='roomResult' style='font-size:12px;margin-top:8px'></div>"
          "</div>"
          "</div>"; // end rooms card
    } // end isLicensed
    html+="</div>"; // /sec-rooms
    server.sendContent(html);html="";

    // SETTINGS TAB
    html+="<div class='section' id='sec-settings'>";
    html+="<div class='card'><div class='lbl'>Security</div>"
          "<form method='POST' action='/changepin'>"
          "<div class='field'><label>Current PIN</label><input type='password' name='oldpin' maxlength='6' required></div>"
          "<div class='field'><label>New PIN (4-6 digits)</label><input type='password' name='newpin' maxlength='6' minlength='4' inputmode='numeric' required></div>"
          "<div class='field'><label>Confirm new PIN</label><input type='password' name='confirmpin' maxlength='6' minlength='4' inputmode='numeric' required></div>"
          "<button class='btn' type='submit'>Change PIN</button>"
          "</form>"
          "<div style='margin-top:12px'>"
          "<form method='POST' action='/revoke'>"
          "<input type='password' name='pin' placeholder='Enter PIN to confirm' style='width:100%;padding:8px;border:1px solid var(--brd);border-radius:6px;background:var(--inp);color:var(--txt);font-size:13px;margin-bottom:8px'>"
          "<button class='btn btn-warn' type='submit'>Broadcast Key Revocation</button>"
          "</form></div></div>";
    html+="<form method='POST' action='/save'>"
          "<div class='card'><div class='lbl'>Privacy &amp; Security</div>"
          "<div class='row' style='align-items:flex-start;gap:12px'>"
          "<div style='flex:1'><label style='font-weight:600'>Show messages on OLED</label>"
          "<div style='font-size:11px;color:#f08040;margin-top:3px'>&#9888; Warning: displays private messages on screen</div>"
          "</div>"
          "<label class='toggle'><input type='checkbox' name='showMsg' value='1' "+String(showMsgOnOLED?"checked":"")+"><span class='slider'></span></label>"
          "</div>"
          "<div class='row'><label>Auto-lock after</label>"
          "<select name='sessMins' style='padding:7px;border:1px solid var(--brd);border-radius:6px;background:var(--inp);color:var(--txt);font-size:13px'>"
          "<option value='1' "+(sessionMinutes==1?"selected":"")+">1 minute</option>"
          "<option value='2' "+(sessionMinutes==2?"selected":"")+">2 minutes</option>"
          "<option value='5' "+(sessionMinutes==5?"selected":"")+">5 minutes</option>"
          "<option value='0' "+(sessionMinutes==0?"selected":"")+">Never</option>"
          "</select></div></div>"
          "<div class='card'><div class='lbl'>Network</div>"
          "<div class='row'><label>WiFi AP</label><input type='checkbox' name='wifiOn' value='1' "+wifiChk+"></div>"
          "<div class='row'><label>Bluetooth</label><input type='checkbox' name='bleOn' value='1' "+bleChk+"></div>"
          "</div>"
          "<div class='card'><div class='lbl'>WiFi</div>"
          "<div class='field'><label>SSID</label><input type='text' name='wifiSSID' value='"+wifiSSID+"' maxlength='32' required></div>"
          "<div class='field'><label>Password</label><input type='password' name='wifiPass' value='"+wifiPass+"' maxlength='64' minlength='8'></div></div>"
          "<div class='card'><div class='lbl'>Bluetooth</div>"
          "<div class='field'><label>Device name</label><input type='text' name='bleName' value='"+bleName+"' maxlength='32' required></div>"
          "<div class='field'><label>BLE PIN</label><input type='password' name='blePin' value='"+blePin+"' maxlength='6' minlength='4' inputmode='numeric'></div></div>";
    // Battery config card
    html+=String("<div class='card'><div class='lbl'>Battery</div>")+
          "<div class='row'><label>Capacity (mAh)</label>"
          "<div style='display:flex;align-items:center;gap:4px'>"
          "<input type='number' name='batCapMah' value='"+String(batCapMah)+"' min='100' max='100000' step='1' list='batCapList' style='width:100px;padding:7px;border:1px solid var(--brd);border-radius:6px;background:var(--inp);color:var(--txt);font-size:13px'>"
          "<datalist id='batCapList'>"
          "<option value='300'><option value='500'><option value='800'>"
          "<option value='1000'><option value='1200'><option value='1500'>"
          "<option value='2000'><option value='2500'><option value='3000'>"
          "<option value='3200'><option value='4000'><option value='5000'>"
          "<option value='6000'><option value='8000'><option value='10000'>"
          "<option value='12000'><option value='15000'><option value='20000'>"
          "</datalist>"
          "<span style='font-size:12px;color:var(--txt3)'>mAh</span></div></div>"          "<div class='row'><label>Chemistry</label>"          "<select name='batLiFePO4' style='padding:7px;border:1px solid var(--brd);border-radius:6px;background:var(--inp);color:var(--txt);font-size:13px'>"          "<option value='' "+(batLiFePO4?"":"selected ")+">LiPo / Li-ion (3.7V)</option>"          "<option value='1' "+(batLiFePO4?"selected ":"")+">LiFePO4 (3.2V)</option>"          "</select></div>"          "<div class='row'><label>Empty (mV)</label>"          "<input type='number' name='batMinMv' value='"+String((int)batMinMv)+"' min='2000' max='3500' step='10' style='width:90px;padding:7px;border:1px solid var(--brd);border-radius:6px;background:var(--inp);color:var(--txt);font-size:13px'></div>"          "<div class='row'><label>Full (mV)</label>"          "<input type='number' name='batMaxMv' value='"+String((int)batMaxMv)+"' min='3500' max='4400' step='10' style='width:90px;padding:7px;border:1px solid var(--brd);border-radius:6px;background:var(--inp);color:var(--txt);font-size:13px'></div>"          "<div class='row'><label>Calibration &times;</label>"
          "<input type='number' name='batDivider' value='"+String(batDivider,3)+"' min='1' max='12' step='0.001' style='width:90px;padding:7px;border:1px solid var(--brd);border-radius:6px;background:var(--inp);color:var(--txt);font-size:13px'></div>"
          "<p class='hint'>Current reading: ~"+String((int)readVbatMv())+" mV &bull; "+String(batPct)+"% ("+String(batCapMah)+" mAh)</p>"          "</div>";
    html+=String("<div class='card'><div class='lbl'>Message alerts</div>")+
          "<p class='hint' style='margin-bottom:6px'>Beep, flash and buzz when a new message arrives. Private and room messages always alert; public messages only if enabled below.</p>"
          "<div class='row'><label>Flash LED</label><label class='toggle'><input type='checkbox' name='alLed' value='1' "+String(alertLedOn?"checked":"")+"><span class='slider'></span></label></div>"
          "<div class='row'><label>Beep</label><label class='toggle'><input type='checkbox' name='alBuzz' value='1' "+String(alertBuzzOn?"checked":"")+"><span class='slider'></span></label></div>"
          "<div class='row'><label>Vibrate</label><label class='toggle'><input type='checkbox' name='alVib' value='1' "+String(alertVibOn?"checked":"")+"><span class='slider'></span></label></div>"
          "<div class='row'><label>Also alert on public channel</label><label class='toggle'><input type='checkbox' name='alPub' value='1' "+String(alertPubOn?"checked":"")+"><span class='slider'></span></label></div>"
          "<button type='button' class='btn-sm' style='margin-top:8px' onclick=\"fetch('/alert-test',{method:'POST'})\">&#128276; Test alert</button>"
          "<p class='hint'>Test fires every fitted part, even if switched off above.</p></div>";
    html+="<div class='card'><button class='btn' type='submit'>Save settings</button></div>"          "</form>";
    html+="<div class='card'><div class='lbl'>Licence</div>"
          "<form method='POST' action='/licence'><div style='display:flex;gap:8px'>"
          "<input type='text' name='key' placeholder='Paste licence key...' style='flex:1;padding:8px;border:1px solid var(--brd);border-radius:6px;background:var(--inp);color:var(--txt);font-size:13px'>"
          "<button type='submit' class='btn-sm'>Apply</button></div>"
          "<p class='hint'>Tied to MAC: "+mac+"</p></form></div>";
    html+="<div class='card' style='text-align:center;padding:12px'><a href='/status'>Raw JSON status</a></div>";
    html+="</div>"; // /sec-settings
    server.sendContent(html);html="";

    // JAVASCRIPT
    html+=R"js(<script>
function goTab(name){
  document.querySelectorAll('.section').forEach(s=>s.classList.remove('active'));
  var sec=document.getElementById('sec-'+name);if(sec)sec.classList.add('active');
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  var nb=document.getElementById('nb-'+name);
  if(nb){nb.classList.add('active');nb.scrollIntoView({behavior:'smooth',block:'nearest',inline:'center'});}
  window.scrollTo(0,0);
}
(function(){
  var b=document.body,t=document.getElementById('dkTog');
  var icon=document.getElementById('modeIcon'),lbl=document.getElementById('modeLabel');
  function sd(on){on?b.classList.add('dark'):b.classList.remove('dark');t.checked=on;
    if(icon)icon.textContent=on?'\u263D':'\u2600';if(lbl)lbl.textContent=on?'Dark':'Light';
    try{localStorage.setItem('plsc_dark',on?'1':'0');}catch(e){}}
  var s=false;try{s=localStorage.getItem('plsc_dark')==='1';}catch(e){}sd(s);
  try{fetch('/time?e='+Math.floor(Date.now()/1000));}catch(e){}
  t.addEventListener('change',function(){sd(this.checked);});
})();
function copyShortCode(){
  var code=document.querySelector('#addContactPanel .monospace,[style*=color\\:#a855f7]');
  var txt=document.querySelector('[style*=\"color:#a855f7\"]');
  var el=document.getElementById('copyShortBtn');
  var code=(el&&el.closest)?el.closest('[style]').previousElementSibling:null;
  // Just copy from the purple short code div
  var allPurple=document.querySelectorAll('[style*=\"color:#a855f7\"]');
  var shortTxt='';for(var i=0;i<allPurple.length;i++){var t=allPurple[i].textContent.trim();if(t.startsWith('PL-')){shortTxt=t;break;}}
  if(shortTxt)try{navigator.clipboard.writeText(shortTxt);}catch(e){}
  if(el){el.textContent='\u2705 Copied!';setTimeout(()=>el.textContent='\uD83D\uDCCB Copy',2000);}
}
function copyPair(){
  var p=document.getElementById('pairPayload').textContent.trim();
  try{if(navigator.clipboard)navigator.clipboard.writeText(p);}catch(e){}
  var el=document.getElementById('copyPairBtn');if(el){el.textContent='\u2705 Copied!';setTimeout(()=>el.textContent='\uD83D\uDCCB Copy full key',2000);}
}
var _loraPollTimer=null;
function sendLoraRequest(){
  var code=document.getElementById('loraShortCode').value.trim().toUpperCase();
  var name=document.getElementById('loraPairName').value.trim();
  var res=document.getElementById('loraReqResult');
  var btn=document.getElementById('loraSendBtn');
  if(!code||code.length<3){res.style.color='#f08080';res.textContent='Enter their short code first';return;}
  if(!code.startsWith('PL-'))code='PL-'+code;
  res.style.color='var(--txt3)';res.textContent='\uD83D\uDCE1 Sending LoRa request...';
  btn.disabled=true;
  fetch('/pair-request',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'code='+encodeURIComponent(code)+'&name='+encodeURIComponent(name||'Contact')
  }).then(r=>r.json()).then(d=>{
    if(d.ok){
      res.style.color='var(--txt3)';res.textContent='\uD83D\uDCE1 Request sent! Waiting for them to accept...';
      if(_loraPollTimer)clearInterval(_loraPollTimer);
      var tries=0;
      _loraPollTimer=setInterval(function(){
        tries++;
        fetch('/pair-status').then(r=>r.json()).then(s=>{
          if(s.paired){clearInterval(_loraPollTimer);res.style.color='#22c55e';res.textContent='\u2705 Paired successfully!';btn.disabled=false;setTimeout(()=>window.location.reload(),1500);}
          else if(s.rejected){clearInterval(_loraPollTimer);res.style.color='#f08080';res.textContent='\u274C Request declined or timed out.';btn.disabled=false;}
          else if(tries>60){clearInterval(_loraPollTimer);res.style.color='#f08080';res.textContent='\u23F1 Timed out — no response. Are they online?';btn.disabled=false;}
          else{res.textContent='\uD83D\uDCE1 Waiting for them to accept... ('+tries+'s)';}
        }).catch(()=>{});
      },1000);
    } else {res.style.color='#f08080';res.textContent='\u274C '+( d.error||'Send failed');btn.disabled=false;}
  }).catch(()=>{res.style.color='#f08080';res.textContent='\u274C Could not connect';btn.disabled=false;});
}
function toggleAddContact(){
  var p=document.getElementById('addContactPanel');if(p)p.style.display=p.style.display!=='none'?'none':'block';
}
function toggleCreateRoom(){
  var p=document.getElementById('createRoomPanel');if(!p)return;var isOpen=p.style.display==='block';p.style.display=isOpen?'none':'block';if(!isOpen){document.getElementById('addMemberPanel').style.display='none';}
}
function addContact(){
  var payload=document.getElementById("pairInput").value.trim();
  var name=document.getElementById("pairName").value.trim();
  var res=document.getElementById("pairResult");
  if(!payload||!payload.startsWith("PLSC:")){res.style.color="#f08080";res.textContent="Key should start with PLSC:";return;}
  res.style.color="var(--txt3)";res.textContent="Adding...";
  fetch("/pair",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},
    body:"payload="+encodeURIComponent(payload)+"&name="+encodeURIComponent(name||"Contact")
  }).then(function(r){
    if(r.ok||r.redirected){res.style.color="#22c55e";res.textContent="\u2705 Added!";
      document.getElementById("pairInput").value="";setTimeout(()=>window.location.reload(),1500);}
    else{res.style.color="#f08080";res.textContent="\u274C Failed";}
  }).catch(()=>{res.style.color="#f08080";res.textContent="\u274C Could not connect.";});
}
function removeContact(id){
  if(!confirm("Remove this contact?"))return;
  fetch("/remove",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"id="+encodeURIComponent(id)}).then(()=>window.location.reload());
}
function editName(id){
  var nm=prompt("New name:");if(nm===null)return;nm=nm.trim();if(!nm)return;
  fetch("/rename",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"id="+encodeURIComponent(id)+"&name="+encodeURIComponent(nm)}).then(()=>window.location.reload());
}
function switchToPrivate(nodeId){goTab('chat');switchTab(nodeId);}
function openVerify(id,name){
  fetch('/verify-words?id='+encodeURIComponent(id)).then(r=>r.json()).then(d=>{
    if(!d.ok){alert('Could not load verification words for this contact.');return;}
    var verified=!!d.verified;
    var chips=(d.words||'').split(' ').filter(Boolean).map(function(w){
      return "<span style='display:inline-block;background:var(--inp);border:0.5px solid var(--brd);border-radius:6px;padding:6px 10px;margin:3px;font-family:monospace;font-size:16px;font-weight:700;color:var(--txt)'>"+w+"</span>";
    }).join('');
    var ov=document.getElementById('verifyOverlay');
    if(!ov){
      ov=document.createElement('div');ov.id='verifyOverlay';
      ov.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;z-index:9999;padding:16px';
      ov.addEventListener('click',function(e){if(e.target===ov)closeVerify();});
      document.body.appendChild(ov);
    }
    var actionBtn = verified
      ? "<button onclick=\"setVerify('"+id+"',0)\" style='flex:1;padding:11px;border-radius:8px;border:0.5px solid var(--brd);background:var(--inp);color:var(--txt);font-weight:700;cursor:pointer'>Clear verification</button>"
      : "<button onclick=\"setVerify('"+id+"',1)\" style='flex:1;padding:11px;border-radius:8px;border:none;background:#1f9d6b;color:#fff;font-weight:700;cursor:pointer'>&#10003; Words match &mdash; mark verified</button>";
    ov.innerHTML="<div style='background:var(--card);border-radius:14px;max-width:430px;width:100%;padding:20px;box-shadow:0 12px 44px rgba(0,0,0,.5)'>"
      +"<div style='font-size:16px;font-weight:700;color:var(--txt);margin-bottom:4px'>Verify "+name+"</div>"
      +"<div style='font-size:12px;color:var(--txt3);line-height:1.5;margin-bottom:14px'>Read these six words aloud over a channel you already trust &mdash; in person or a phone call. If they match on both devices, your connection is genuine and has not been intercepted.</div>"
      +"<div style='text-align:center;margin-bottom:16px'>"+chips+"</div>"
      +(verified?"<div style='text-align:center;color:#1f9d6b;font-size:12px;margin-bottom:12px;font-weight:700'>&#10003; Currently verified</div>":"")
      +"<div style='display:flex;gap:8px'>"+actionBtn
      +"<button onclick='closeVerify()' style='padding:11px 14px;border-radius:8px;border:0.5px solid var(--brd);background:var(--inp);color:var(--txt);cursor:pointer'>Close</button>"
      +"</div></div>";
    ov.style.display='flex';
  }).catch(function(){alert('Verification request failed.');});
}
function closeVerify(){var ov=document.getElementById('verifyOverlay');if(ov)ov.style.display='none';}
function setVerify(id,v){
  fetch('/verify-set',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'id='+encodeURIComponent(id)+'&v='+v}).then(()=>window.location.reload());
}
function openRoom(rid){goTab('chat');switchTab('room_'+rid);}
function leaveRoom(rid){if(!confirm('Leave this room?'))return;fetch('/room-leave',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'id='+encodeURIComponent(rid)}).then(()=>window.location.reload());}
function createRoom(){
  var name=document.getElementById('rName').value.trim();
  if(!name){alert('Please enter a room name');return;}
  var maxMsgs=document.getElementById('rMaxMsgs')?document.getElementById('rMaxMsgs').value:'50';
  var priv=document.getElementById('rPrivate')&&document.getElementById('rPrivate').checked?'1':'0';
  var members=[];
  document.querySelectorAll('input[name=roomMember]:checked').forEach(function(cb){members.push(cb.value);});
  var el=document.getElementById('roomResult');
  if(el)el.innerHTML='<span style="color:var(--txt3)">Creating room\u2026</span>';
  fetch('/room-create',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'name='+encodeURIComponent(name)+'&maxMsgs='+maxMsgs+'&priv='+priv+'&members='+members.join(',')
  }).then(function(r){return r.json();}).then(function(d){
    if(el)el.innerHTML=d.ok?'<span style="color:#0f6e56">\u2705 Room created \u2014 invited '+d.invited+' contact(s).</span>':'<span style="color:#c00">Failed: '+d.error+'</span>';
    if(d.ok)setTimeout(function(){window.location.reload();},1200);
  }).catch(function(){if(el)el.innerHTML='<span style="color:#c00">Request failed</span>';});
}

function showAddMembers(rid){
  var p=document.getElementById('addMemberPanel');if(!p)return;
  p.dataset.rid=rid;p.style.display=p.style.display==='none'||p.style.display===''?'block':'none';
  document.getElementById('createRoomPanel').style.display='none';
  var ri=document.getElementById('addRoomName');
  if(ri){var rEl=document.querySelector('[data-rid="'+rid+'"] .room-name');ri.textContent=rEl?rEl.textContent:rid;}
}
function submitAddMembers(){
  var p=document.getElementById('addMemberPanel');if(!p)return;
  var rid=p.dataset.rid;var members=[];
  document.querySelectorAll('input[name=addMember]:checked').forEach(function(cb){members.push(cb.value);});
  if(!members.length){alert('Select at least one contact');return;}
  var el=document.getElementById('addResult');if(el)el.innerHTML='Sending invites\u2026';
  fetch('/room-invite',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'id='+rid+'&members='+members.join(',')
  }).then(function(r){return r.json();}).then(function(d){
    if(el)el.innerHTML=d.ok?'\u2705 Invited '+d.invited+' contact(s).':'\u274C Failed: '+d.error;
    if(d.ok)setTimeout(function(){window.location.reload();},1200);
  }).catch(function(){if(el)el.innerHTML='\u274C Request failed';});
}
function renameRoom(rid){
  var cur=document.querySelector('[data-rid="'+rid+'"] div div');
  var name=prompt('New room name:',cur?cur.textContent.replace('\uD83D\uDC65 ','').trim():'');
  if(!name||!name.trim())return;
  fetch('/room-rename',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'id='+rid+'&name='+encodeURIComponent(name.trim())
  }).then(function(){window.location.reload();}).catch(function(){alert('Failed to rename');});
}
function lockNow(){fetch('/lock',{method:'POST'}).then(()=>window.location.replace('/?locked=1')).catch(()=>window.location.replace('/?locked=1'));}
function confirmMsgToggle(cb){if(cb.checked&&!confirm("\u26A0 This displays private messages on the OLED screen.\nAnyone near the device can read them.\n\nAre you sure?")){cb.checked=false;}}
var allMsgs=[],activeTab='pub',unreadTabs={},unreadCounts={};
function switchTab(tab){
  activeTab=tab;
  document.querySelectorAll('.chat-tab').forEach(el=>{el.classList.remove('active');if(el.id==='tab_'+tab){el.classList.add('active');el.classList.remove('unread');}});
  var lbl=document.getElementById('chatToLabel');
  var hiddenTo=document.getElementById('chatTo');hiddenTo.value=tab;
  if(tab==='pub'){lbl.innerHTML='&#127760; Broadcasting to <b>public channel</b>';}
  else if(tab.indexOf('room_')===0){var rEl=document.getElementById('tab_'+tab);var rn=rEl?rEl.getAttribute('data-nm'):'Room';lbl.innerHTML='&#128101; Room <b>'+rn+'</b>';}
  else{var tabEl=document.getElementById('tab_'+tab);var nm=tabEl?tabEl.getAttribute('data-nm'):'Contact';lbl.innerHTML='&#128274; Private to <b>'+nm+'</b>';fetch('/read?from='+encodeURIComponent(tab)).catch(()=>{});}
  delete unreadTabs[tab];unreadCounts[tab]=0;updateTitle();renderMsgs();updateChatBadges();
  document.getElementById('msgInp').focus();
}
function fmtAgo(s){if(s===undefined||s<0)return 'earlier';if(s<5)return 'now';if(s<60)return s+'s ago';if(s<3600)return Math.floor(s/60)+'m ago';return Math.floor(s/3600)+'h ago';}
function renderMsgs(){
  var box=document.getElementById('chatBox');
  var visible=allMsgs.filter(function(m){
    if(activeTab.indexOf('room_')===0){var rid=activeTab.substring(5).toLowerCase();return m.room&&m.room.toLowerCase()===rid;}
    if(activeTab==='pub') return !m.priv&&(!m.room||m.room==='00000000');
    if(!m.priv)return false;
    if(!m.me)return m.from===activeTab;
    return m.to===activeTab||m.to===activeTab.toLowerCase();
  });
  if(visible.length===0){box.innerHTML="<div style='color:var(--txt3);font-size:12px;padding:8px'>No messages yet</div>";return;}
  var atBottom=box.scrollTop+box.clientHeight>=box.scrollHeight-10;
  box.innerHTML='';
  visible.forEach(function(m){
    var wrap=document.createElement('div');
    wrap.style.cssText='display:flex;flex-direction:column;margin-bottom:2px;'+(m.me?'align-items:flex-end':'align-items:flex-start');
    var d=document.createElement('div');
    d.className='chat-msg '+(m.me?'me':m.priv?'priv':'pub');
    if(!m.me){var f=document.createElement('div');f.className='chat-from';f.textContent=(m.priv?'\uD83D\uDD12 ':'\uD83C\uDF10 ')+m.name;d.appendChild(f);}
    var t=document.createElement('div');t.textContent=m.text;d.appendChild(t);
    wrap.appendChild(d);
    var tm=document.createElement('div');tm.style.cssText='font-size:10px;color:var(--txt3);margin:1px 5px 4px';tm.textContent=fmtAgo(m.ago);
    if(m.me&&m.priv){var tk=document.createElement('span');var st=m.status||0;tk.style.cssText='margin-left:5px;font-weight:700;'+(st>=2?'color:#3b82f6':'color:var(--txt3)');tk.textContent=st>=1?'\u2713\u2713':'\u2713';tm.appendChild(tk);}
    wrap.appendChild(tm);box.appendChild(wrap);
  });
  if(atBottom)box.scrollTop=box.scrollHeight;
}
function updateChatBadges(){
  var total=0;for(var k in unreadCounts)total+=unreadCounts[k]||0;
  document.querySelectorAll('.chat-tab').forEach(function(el){
    var id=el.id.indexOf('tab_')===0?el.id.substring(4):'';var n=unreadCounts[id]||0;
    var badge=el.querySelector('.tabcount');
    if(n>0){if(!badge){badge=document.createElement('span');badge.className='tabcount';el.appendChild(badge);}badge.textContent=n;}
    else if(badge)badge.parentNode.removeChild(badge);
  });
  var nb=document.getElementById('navBadgeChat');
  if(nb){if(total>0){nb.textContent=total;nb.style.display='';}else{nb.textContent='';nb.style.display='none';}}
}
function updateTitle(){var n=Object.keys(unreadTabs).length;document.title=(n>0?'('+n+') ':'')+'PLSChat';}
var LICENSED=false,pubLeft=-1,notifReady=false,lastMC=0;
function updateLicenceUI(){
  var h=document.getElementById('licHint');if(!h)return;
  if(LICENSED){h.style.display='none';return;}
  h.style.display='block';
  h.innerHTML='\uD83D\uDD13 Free: '+(pubLeft<0?0:pubLeft)+'/10 public msgs. Private needs a <b>licence</b>.';
}
function updateCharCount(){var inp=document.getElementById('msgInp');var el=document.getElementById('charCount');if(!inp||!el)return;var n=inp.value.length;el.textContent=n>0?n+'/400':'';}
function splitMsg(t,n){var parts=[],r=t;while(r.length>n){var slice=r.substring(0,n);var sp=slice.lastIndexOf(' ');if(sp>n*0.5){parts.push(r.substring(0,sp));r=r.substring(sp+1);}else{parts.push(slice);r=r.substring(n);}}if(r.length>0)parts.push(r);return parts;}
function sendMsg(){
  var inp=document.getElementById('msgInp');var to=document.getElementById('chatTo').value;
  var txt=inp.value.trim();if(!txt)return;
  if(!LICENSED&&to!=='pub'){alert('Private chats need a licence \u2014 add one in Settings.');return;}
  inp.value='';updateCharCount();
  var isRoom=to.indexOf('room_')===0;
  var parts=txt.length<=63?[txt]:splitMsg(txt,52);var total=parts.length;
  var bodies=parts.map((p,i)=>total>1?('('+(i+1)+'/'+total+') '+p):p);
  bodies.forEach((body)=>allMsgs.push({from:'me',name:'You',text:body,me:true,priv:(!isRoom&&to!=='pub'),to:to,room:isRoom?to.substring(5):'00000000',ago:0,status:0}));
  renderMsgs();
  bodies.forEach((body,i)=>setTimeout(()=>{
    fetch('/send',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'msg='+encodeURIComponent(body)+'&to='+encodeURIComponent(to)
    }).then(r=>r.json()).then(d=>{if(d&&!d.ok&&d.reason==='cap'){var h=document.getElementById('licHint');if(h){h.style.display='block';h.innerHTML='\u26A0 Free limit reached.';}}setTimeout(fetchMsgs,500);}).catch(()=>{});
  },i*1400));
}
document.getElementById('msgInp').addEventListener('keypress',function(e){if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMsg();}});
function beep(){try{var Ctx=window.AudioContext||window.webkitAudioContext;if(!Ctx)return;if(!window._ac)window._ac=new Ctx();var ac=window._ac,o=ac.createOscillator(),g=ac.createGain();o.type='sine';o.frequency.value=880;g.gain.value=0.06;o.connect(g);g.connect(ac.destination);o.start();g.gain.exponentialRampToValueAtTime(0.0001,ac.currentTime+0.18);o.stop(ac.currentTime+0.2);}catch(e){}}
function fetchMsgs(){
  fetch('/messages').then(r=>{if(r.status===403){window.location.reload();return Promise.reject('locked');}return r.json();}).then(msgs=>{
    if(!msgs)return;var prevLen=allMsgs.length;allMsgs=msgs;
    if(notifReady&&msgs.length>prevLen){
      var gotNew=false;
      msgs.slice(prevLen).forEach(m=>{if(m.me)return;var tab=m.priv?m.from:(m.room&&m.room!=='00000000'?'room_'+m.room:'pub');if(tab!==activeTab){unreadTabs[tab]=true;unreadCounts[tab]=(unreadCounts[tab]||0)+1;gotNew=true;}});
      Object.keys(unreadTabs).forEach(tab=>{var el=document.getElementById('tab_'+tab);if(el&&!el.classList.contains('active'))el.classList.add('unread');});
      if(gotNew){beep();updateTitle();}
    }
    notifReady=true;renderMsgs();updateChatBadges();
  }).catch(()=>{});
}
function pollStatus(){
  fetch('/status').then(r=>r.json()).then(d=>{
    var bigEl=document.getElementById('sigBig'),qualEl=document.getElementById('sigQual'),subEl=document.getElementById('sigSub'),barEl=document.getElementById('sigBar');
    var cv=document.getElementById('cntVal'),lv=document.getElementById('loraVal');
    if(cv)cv.textContent=d.contacts||0;
    LICENSED=!!d.licensed;pubLeft=d.pub_left===undefined?-1:d.pub_left;updateLicenceUI();
    var rssi=d.lora_rssi||0,snr=d.lora_snr||0,rx=d.pkt_rx||0;
    if(!d.lora_ready){if(bigEl)bigEl.textContent='--';if(qualEl)qualEl.textContent='LoRa failed';if(barEl)barEl.style.width='0%';}
    else if(rx===0){if(bigEl)bigEl.textContent='--';if(qualEl)qualEl.textContent='Listening...';}
    else{
      if(bigEl)bigEl.textContent=rssi+' dBm';
      if(barEl){var pct=Math.max(0,Math.min(100,((rssi+140)/60)*100));barEl.style.width=pct+'%';}
      var qual,col;
      if(rssi>=-100&&snr>=5){qual='STRONG';col='#00d4aa';}else if(rssi>=-110&&snr>=0){qual='GOOD';col='#4caf50';}else if(rssi>=-120&&snr>=-5){qual='FAIR';col='#ff9800';}else{qual='WEAK';col='#f44336';}
      if(qualEl){qualEl.textContent=qual;qualEl.style.color=col;}if(barEl)barEl.style.background=col;if(bigEl)bigEl.style.color=col;
      if(subEl)subEl.textContent='SNR:'+snr.toFixed(1)+'dB Rx:'+rx+' Relay:'+d.pkt_relay;
      if(lv)lv.textContent=rssi+' dBm';
    }
    if(d.msg_count!==lastMC){lastMC=d.msg_count;fetchMsgs();}
  }).catch(()=>{});
}
function checkIncomingPair(){
  fetch("/pair-incoming").then(r=>r.json()).then(d=>{
    if(d.accepted){var el=document.getElementById("incomingPairAlert");if(el)el.remove();return;}
    if(d.pending){
      if(!document.getElementById("incomingPairAlert")){
        var alert=document.createElement("div");alert.id="incomingPairAlert";
        alert.style.cssText="position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#1e2937;border:2px solid #a855f7;border-radius:12px;padding:16px 20px;z-index:999;text-align:center;min-width:280px";
        alert.innerHTML="<div style='font-weight:700;margin-bottom:8px'>&#128226; Pairing Request</div>"
          +"<div style='font-size:12px;color:var(--txt3);margin-bottom:12px'>From: "+d.from+"</div>"
          +"<input id='incPairName' type='text' placeholder='Their name' maxlength='15' style='width:100%;padding:8px;margin-bottom:10px;border-radius:6px;border:1px solid #334155;background:#12121f;color:#fff;box-sizing:border-box'>"
          +"<div style='display:flex;gap:8px'>"
          +"<button onclick='acceptPair()' style='flex:1;padding:10px;background:#22c55e;color:#000;border:none;border-radius:8px;font-weight:700;cursor:pointer'>&#10003; Accept</button>"
          +"<button onclick='rejectPair()' style='flex:1;padding:10px;background:#c00;color:#fff;border:none;border-radius:8px;font-weight:700;cursor:pointer'>&#10007; Reject</button>"
          +"</div>";
        document.body.appendChild(alert);
      }
    } else {var el=document.getElementById("incomingPairAlert");if(el)el.remove();}
  }).catch(()=>{});
}
var pairAccepting=false;
function acceptPair(){
  if(pairAccepting)return;pairAccepting=true;
  var name=document.getElementById("incPairName").value.trim()||"Contact";
  fetch("/pair-accept",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"name="+encodeURIComponent(name)})
  .then(r=>r.json()).then(d=>{
    var el=document.getElementById("incomingPairAlert");
    if(d.ok){if(el)el.innerHTML="<div style='text-align:center;padding:16px;color:#22c55e;font-size:18px'>\u2713 Paired!</div>";setTimeout(()=>{if(el)el.remove();window.location.reload();},1500);}
    else{if(el)el.remove();pairAccepting=false;}
  }).catch(()=>{var el=document.getElementById("incomingPairAlert");if(el)el.remove();pairAccepting=false;});
}
function rejectPair(){var el=document.getElementById("incomingPairAlert");if(el)el.remove();}
fetchMsgs();pollStatus();
setInterval(pollStatus,2000);setInterval(fetchMsgs,1500);setInterval(checkIncomingPair,3000);
</script></div></body></html>)js";
    server.sendContent(html);html="";
    server.sendContent("");
    Serial.printf("[Web] streamed page in %lu ms\n",millis()-_pgT0);
  });

  server.on("/rename",HTTP_POST,[](){
    if(!checkSessionCookie()){server.send(403,"text/plain","locked");return;}
    uint32_t id=(uint32_t)strtoul(server.arg("id").c_str(),nullptr,16);
    String nm=server.arg("name");
    if(renameContact(id,nm))server.send(200,"text/plain","ok");
    else server.send(400,"text/plain","fail");
  });
  server.on("/unlock",HTTP_POST,[](){
    if(deviceUnlocked){server.sendHeader("Location","/");server.send(302,"text/plain","");return;}
    String pin=server.arg("pin");pin.trim();
    secPrefs.begin("security",true);
    int attempts=secPrefs.getInt("pinAttempts",0);
    unsigned long lockUntil=secPrefs.getULong("lockUntil",0);
    secPrefs.end();
    if(lockUntil>0&&millis()<lockUntil){server.sendHeader("Location","/?locked=1");server.send(302,"text/plain","");return;}
    if(checkPin(pin)){
      secPrefs.begin("security",false);secPrefs.putInt("pinAttempts",0);secPrefs.putULong("lockUntil",0);secPrefs.end();
      startWebSession();Serial.println("[Security] Unlocked via web");setSessionCookie();
      server.send(200,"text/html","<!DOCTYPE html><html><head><meta charset='utf-8'><meta http-equiv='refresh' content='0;url=/'></head><body style='background:#0d0d1a;color:#a855f7;text-align:center;padding-top:60px'>Unlocking&hellip;</body></html>");
    } else {
      attempts++;unsigned long lockMs=0;
      if(attempts>=PIN_WIPE_ATTEMPTS){wipeDevice();}
      else if(attempts>=PIN_MAX_ATTEMPTS){lockMs=(unsigned long)PIN_LOCKOUT_MS*(1<<(attempts-PIN_MAX_ATTEMPTS));}
      secPrefs.begin("security",false);secPrefs.putInt("pinAttempts",attempts);
      if(lockMs>0)secPrefs.putULong("lockUntil",millis()+lockMs);secPrefs.end();
      server.sendHeader("Location","/?wrong=1");server.send(302,"text/plain","");
    }
  });
  server.on("/setpin",HTTP_POST,[](){
    if(isPinSet()&&!deviceUnlocked){server.sendHeader("Location","/");server.send(302,"text/plain","");return;}
    String pin=server.arg("pin"),pin2=server.arg("pin2");pin.trim();pin2.trim();
    if(pin==pin2&&(int)pin.length()>=PIN_MIN_LENGTH&&pin.length()==strspn(pin.c_str(),"0123456789")){
      setPin(pin);clearFirstBoot();startWebSession();setSessionCookie();
      server.send(200,"text/html","<!DOCTYPE html><html><head><meta charset='utf-8'><meta http-equiv='refresh' content='0;url=/'></head><body style='background:#0d0d1a;color:#a855f7;text-align:center;padding-top:60px'>Starting&hellip;</body></html>");
    } else {server.sendHeader("Location","/?pinfail=1");server.send(302,"text/plain","");}
  });
  server.on("/alert-test",HTTP_POST,[](){
    if(!checkSessionCookie()){server.send(403,"text/plain","auth");return;}
    alertStart(ALERT_PRIV,true);server.send(200,"application/json","{\"ok\":true}");
  });
  server.on("/touch",HTTP_POST,[](){if(checkSessionCookie())touchSession();server.send(200,"text/plain","ok");});
  server.on("/lock",HTTP_POST,[](){
    deviceUnlocked=false;sessionToken="";
    server.sendHeader("Set-Cookie",String(SESSION_COOKIE)+"=; Path=/; Max-Age=0");
    server.sendHeader("Location","/?locked=1");server.send(302,"text/plain","");
  });
  server.on("/pair",HTTP_POST,[](){
    if(!checkSessionCookie()){server.send(403,"text/plain","Locked");return;}
    if(!server.hasArg("payload")){server.sendHeader("Location","/?pairfail=1");server.send(302,"text/plain","");return;}
    String payload=server.arg("payload"),name=server.hasArg("name")?server.arg("name"):"";
    payload.trim();name.trim();
    uint8_t sk[AES_KEY_SIZE];uint32_t nodeId=parsePairingPayload(payload,sk);
    if(nodeId==0||nodeId==getMyNodeId())server.sendHeader("Location","/?pairfail=1");
    else addContact(nodeId,sk,name)?server.sendHeader("Location","/?paired=1"):server.sendHeader("Location","/?pairfail=1");
    server.send(302,"text/plain","");if(oledOn)updateOLED();
  });
  server.on("/remove",HTTP_POST,[](){
    if(!checkSessionCookie()){server.send(403,"text/plain","Locked");return;}
    if(server.hasArg("id")){uint32_t id=(uint32_t)strtoul(server.arg("id").c_str(),nullptr,16);removeContact(id);}
    server.sendHeader("Location","/?removed=1");server.send(302,"text/plain","");if(oledOn)updateOLED();
  });
  server.on("/verify-words",HTTP_GET,[](){
    if(!checkSessionCookie()){server.send(403,"text/plain","Locked");return;}
    uint32_t id=(uint32_t)strtoul(server.arg("id").c_str(),nullptr,16);
    if(id==0||!isContact(id)){server.send(400,"application/json","{\"ok\":false}");return;}
    String j="{\"ok\":true,\"verified\":";j+=(isContactVerified(id)?"true":"false");
    j+=",\"words\":\"";j+=getSafetyWords(id);j+="\"}";
    server.send(200,"application/json",j);
  });
  server.on("/verify-set",HTTP_POST,[](){
    if(!checkSessionCookie()){server.send(403,"text/plain","Locked");return;}
    uint32_t id=(uint32_t)strtoul(server.arg("id").c_str(),nullptr,16);
    if(id==0||!isContact(id)){server.send(400,"application/json","{\"ok\":false}");return;}
    setContactVerified(id,server.arg("v")=="1");
    server.send(200,"application/json","{\"ok\":true}");
  });
  server.on("/time",HTTP_GET,[](){
    if(!checkSessionCookie()){server.send(403,"text/plain","Locked");return;}
    uint32_t t=(uint32_t)strtoul(server.arg("e").c_str(),nullptr,10);
    if(t>1700000000UL){ // sanity check: must look like a real unix epoch
      timeSyncEpoch=t;timeSyncLifetimeSecs=lifetimeSeconds;timeSynced=true;
      prefs.putUInt("tsEpoch",timeSyncEpoch);prefs.putULong("tsLife",timeSyncLifetimeSecs);
      server.send(200,"application/json","{\"ok\":true}");
    } else server.send(200,"application/json","{\"ok\":false}");
  });
  server.on("/send",HTTP_POST,[](){
    if(!checkSessionCookie()){server.send(403,"text/plain","Locked");return;}
    if(server.hasArg("msg")){
      String msg=server.arg("msg"),to=server.hasArg("to")?server.arg("to"):"pub";
      msg.trim();if(msg.length()>0){
        if(to=="pub"){
          if(!consumePublicQuota()){server.send(200,"application/json","{\"ok\":false,\"reason\":\"cap\"}");return;}
          sendPublicMessage(msg);
        } else if(to.startsWith("room_")){
          if(!isLicensed){server.send(200,"application/json","{\"ok\":false,\"reason\":\"licence\"}");return;}
          uint32_t rid=(uint32_t)strtoul(to.substring(5).c_str(),nullptr,16);if(rid)sendRoomMessage(rid,msg);
        } else {
          if(!isLicensed){server.send(200,"application/json","{\"ok\":false,\"reason\":\"licence\"}");return;}
          uint32_t id=(uint32_t)strtoul(to.c_str(),nullptr,16);if(id)sendPrivateMessage(id,msg);
        }
      }
    }
    server.send(200,"application/json","{\"ok\":true}");
  });
  server.on("/room-create",HTTP_POST,[](){
    if(!checkSessionCookie()){server.send(403,"application/json","{\"ok\":false}");return;}
    if(!isLicensed){server.send(200,"application/json","{\"ok\":false,\"error\":\"Licence required\"}");return;}
    String name=server.hasArg("name")?server.arg("name"):"";name.trim();
    if(name.length()==0){server.send(200,"application/json","{\"ok\":false,\"error\":\"no name\"}");return;}
    if(countRooms()>=MAX_ROOMS){server.send(200,"application/json","{\"ok\":false,\"error\":\"room limit reached\"}");return;}
    bool priv=server.hasArg("priv")&&server.arg("priv")=="1";
    uint8_t maxM=(uint8_t)constrain(server.hasArg("maxMsgs")?server.arg("maxMsgs").toInt():50,10,200);
    uint32_t rid=0;mbedtls_ctr_drbg_random(&ctrDrbg,(uint8_t*)&rid,4);if(rid==0)rid=1;
    uint8_t rkey[AES_KEY_SIZE];mbedtls_ctr_drbg_random(&ctrDrbg,rkey,AES_KEY_SIZE);
    if(!addRoom(rid,rkey,name.c_str(),priv,maxM)){server.send(200,"application/json","{\"ok\":false,\"error\":\"store failed\"}");return;}
    addRoomMember(rid,getMyNodeId());
    int invited=0;
    if(server.hasArg("members")){
      String mem=server.arg("members");int start=0;
      while(start<(int)mem.length()){
        int comma=mem.indexOf(',',start);
        String tok=(comma<0)?mem.substring(start):mem.substring(start,comma);tok.trim();
        if(tok.length()>0){uint32_t cid=(uint32_t)strtoul(tok.c_str(),nullptr,16);if(cid&&isContact(cid)){sendRoomInvite(cid,rid);addRoomMember(rid,cid);invited++;delay(400);}}
        if(comma<0)break;start=comma+1;
      }
    }
    char resp[96];snprintf(resp,sizeof(resp),"{\"ok\":true,\"roomId\":\"%08X\",\"invited\":%d}",rid,invited);
    server.send(200,"application/json",resp);
  });
  server.on("/room-leave",HTTP_POST,[](){
    if(!checkSessionCookie()){server.send(403,"text/plain","Locked");return;}
    if(server.hasArg("id")){uint32_t rid=(uint32_t)strtoul(server.arg("id").c_str(),nullptr,16);if(rid)deleteRoom(rid);}
    server.send(200,"text/plain","ok");
  });
  server.on("/room-rename",HTTP_POST,[](){
    if(!checkSessionCookie()){server.send(403,"application/json","{\"ok\":false}");return;}
    if(!server.hasArg("id")||!server.hasArg("name")){server.send(200,"application/json","{\"ok\":false,\"error\":\"missing\"}");return;}
    uint32_t rid=(uint32_t)strtoul(server.arg("id").c_str(),nullptr,16);
    int i=findRoom(rid);if(i<0){server.send(200,"application/json","{\"ok\":false,\"error\":\"not found\"}");return;}
    String nm=server.arg("name");nm.trim();if(nm.length()==0){server.send(200,"application/json","{\"ok\":false,\"error\":\"empty\"}");return;}
    strncpy(rooms[i].name,nm.c_str(),ROOM_NAME_LEN-1);rooms[i].name[ROOM_NAME_LEN-1]=0;
    saveRooms();server.send(200,"application/json","{\"ok\":true}");
  });
  server.on("/read",HTTP_GET,[](){
    if(!checkSessionCookie()){server.send(403,"text/plain","Locked");return;}
    if(server.hasArg("from")){uint32_t from=(uint32_t)strtoul(server.arg("from").c_str(),nullptr,16);if(from){uint32_t nonce;mbedtls_ctr_drbg_random(&ctrDrbg,(uint8_t*)&nonce,4);sendAck(from,nonce,PKT_TYPE_READ);}}
    server.send(200,"text/plain","ok");
  });
  server.on("/messages",HTTP_GET,[](){
    if(!checkSessionCookie()){server.send(403,"application/json","[]");return;}
    alertClearUnread();   // the chat is open and has fetched messages -> seen
    String json="[";int count=min(messageCount,MAX_MESSAGES);
    for(int i=0;i<count;i++){
      int idx=(messageHead-count+i+MAX_MESSAGES)%MAX_MESSAGES;
      ChatMessage& m=messageStore[idx];
      if(i>0)json+=",";
      String name=m.isMe?"You":getContactName(m.fromNode);
      String text=m.text;text.replace("\"","\\\"");text.replace("\n"," ");
      char nid[12];sprintf(nid,"%08X",m.fromNode);
      char toNid[12];sprintf(toNid,"%08X",m.isMe&&m.isPrivate?m.toNode:0);
      char rmid[12];sprintf(rmid,"%08X",m.roomId);
      unsigned long nowMs=millis();long ago=(nowMs>=m.timestamp)?(long)((nowMs-m.timestamp)/1000):-1;
      json+="{\"from\":\""+String(nid)+"\",\"name\":\""+name+"\","
            "\"to\":\""+String(toNid)+"\","
            "\"room\":\""+String(rmid)+"\","
            "\"status\":"+String((m.isMe&&m.isPrivate)?(int)m.status:0)+","
            "\"priv\":"+(m.isPrivate?"true":"false")+","
            "\"me\":"+(m.isMe?"true":"false")+","
            "\"ago\":"+String(ago)+","
            "\"text\":\""+text+"\"}";
    }
    json+="]";server.send(200,"application/json",json);
  });
  server.on("/pair-incoming",HTTP_GET,[](){
    if(!checkSessionCookie()){server.send(403,"application/json","{}");return;}
    if(incomingPair.accepted){
      if(millis()-incomingPair.acceptedAt>3000)incomingPair.accepted=false;
      server.send(200,"application/json","{\"pending\":false,\"accepted\":true}");return;
    }
    if(!incomingPair.pending||millis()-incomingPair.receivedAt>PAIR_REQUEST_TIMEOUT){
      incomingPair.pending=false;server.send(200,"application/json","{\"pending\":false}");return;
    }
    char nid[12];sprintf(nid,"%08X",incomingPair.fromNode);
    server.send(200,"application/json","{\"pending\":true,\"from\":\""+String(nid)+"\"}");
  });
  server.on("/pair-accept",HTTP_POST,[](){
    if(!checkSessionCookie()){server.send(403,"text/plain","Locked");return;}
    if(!incomingPair.pending){server.send(200,"application/json","{\"ok\":false,\"error\":\"not pending\"}");return;}
    String name=server.arg("name");if(name.length()==0)name="Contact";
    uint8_t sharedKey[32];
    if(computeSharedSecretFromPubKey(incomingPair.pubKey,sharedKey)){
      if(addContact(incomingPair.fromNode,sharedKey,name.c_str())){
        uint8_t pkt[41];pkt[0]=PKT_TYPE_PAIR_ACK;
        uint32_t myId=getMyNodeId();
        pkt[1]=(myId>>24)&0xFF;pkt[2]=(myId>>16)&0xFF;pkt[3]=(myId>>8)&0xFF;pkt[4]=myId&0xFF;
        uint32_t theirId=incomingPair.fromNode;
        pkt[5]=(theirId>>24)&0xFF;pkt[6]=(theirId>>16)&0xFF;pkt[7]=(theirId>>8)&0xFF;pkt[8]=theirId&0xFF;
        memcpy(&pkt[9],myPublicKey,CURVE25519_KEY_SIZE);
        radio.transmit(pkt,41);radio.startReceive();
        incomingPair.pending=false;incomingPair.accepted=true;incomingPair.acceptedAt=millis();incomingPair.fromNode=0;
        server.send(200,"application/json","{\"ok\":true}");
      } else {incomingPair.pending=false;server.send(200,"application/json","{\"ok\":false,\"error\":\"contacts full\"}");}
    } else {incomingPair.pending=false;server.send(200,"application/json","{\"ok\":false,\"error\":\"crypto failed\"}");}
  });
  server.on("/pair-request",HTTP_POST,[](){
    if(!checkSessionCookie()){server.send(403,"text/plain","Locked");return;}
    String code=server.arg("code");code.trim();String name=server.arg("name");name.trim();
    if(name.length()==0)name="Contact";
    if(!loraReady||!cryptoReady){server.send(200,"application/json","{\"ok\":false,\"error\":\"LoRa not ready\"}");return;}
    uint8_t pkt[45];pkt[0]=PKT_TYPE_PAIR_REQ;
    uint32_t myId=getMyNodeId();
    pkt[1]=(myId>>24)&0xFF;pkt[2]=(myId>>16)&0xFF;pkt[3]=(myId>>8)&0xFF;pkt[4]=myId&0xFF;
    String shortCode=code.startsWith("PL-")?code.substring(3):code;shortCode=shortCode.substring(0,8);
    for(int i=0;i<8;i++)pkt[5+i]=(i<(int)shortCode.length())?shortCode[i]:0;
    memcpy(&pkt[13],myPublicKey,CURVE25519_KEY_SIZE);
    int r=radio.transmit(pkt,45);
    if(r==RADIOLIB_ERR_NONE){
      pairReq.pending=true;pairReq.accepted=false;pairReq.rejected=false;
      pairReq.name=name;pairReq.nodeId=0;pairReq.sentAt=millis();
      radio.startReceive();server.send(200,"application/json","{\"ok\":true}");
    } else {radio.startReceive();server.send(200,"application/json","{\"ok\":false,\"error\":\"transmit failed\"}");}
  });
  server.on("/pair-status",HTTP_GET,[](){
    if(!checkSessionCookie()){server.send(403,"text/plain","Locked");return;}
    if(pairReq.pending&&millis()-pairReq.sentAt>PAIR_REQUEST_TIMEOUT){pairReq.pending=false;pairReq.rejected=true;}
    String json="{\"pending\":"+(String)(pairReq.pending?"true":"false")+",\"paired\":"+(String)(pairReq.accepted?"true":"false")+",\"rejected\":"+(String)(pairReq.rejected?"true":"false")+"}";
    if(pairReq.accepted){pairReq.accepted=false;pairReq.pending=false;}
    server.send(200,"application/json",json);
  });
  server.on("/changepin",HTTP_POST,[](){
    if(!checkSessionCookie()){server.send(403,"text/plain","Locked");return;}
    String oldpin=server.arg("oldpin"),newpin=server.arg("newpin"),confirm=server.arg("confirmpin");
    oldpin.trim();newpin.trim();confirm.trim();
    if(!checkPin(oldpin)||newpin!=confirm||(int)newpin.length()<PIN_MIN_LENGTH)server.sendHeader("Location","/?pinfail=1");
    else{setPin(newpin);server.sendHeader("Location","/?pinok=1");}
    server.send(302,"text/plain","");
  });
  server.on("/revoke",HTTP_POST,[](){
    if(!checkSessionCookie()){server.send(403,"text/plain","Locked");return;}
    String pin=server.arg("pin");pin.trim();
    if(checkPin(pin)){sendRevocation();server.sendHeader("Location","/?saved=1");}
    else server.sendHeader("Location","/?pinfail=1");
    server.send(302,"text/plain","");
  });
  server.on("/save",HTTP_POST,[](){
    if(!checkSessionCookie()){server.send(403,"text/plain","Locked");return;}
    String ns=server.arg("wifiSSID"),np=server.arg("wifiPass"),nb=server.arg("bleName"),nk=server.arg("blePin");
    bool nw=server.hasArg("wifiOn"),nb2=server.hasArg("bleOn");
    if(!nw&&!nb2)nw=true;
    ns.trim();np.trim();nb.trim();nk.trim();
    if(ns.length()>0)wifiSSID=ns;if(np.length()>=8)wifiPass=np;
    if(nb.length()>0)bleName=nb;if(nk.length()>=4)blePin=nk;
    wifiEnabled=nw;bleEnabled=nb2;
    showMsgOnOLED=server.hasArg("showMsg");
    alertLedOn=server.hasArg("alLed");alertBuzzOn=server.hasArg("alBuzz");alertVibOn=server.hasArg("alVib");alertPubOn=server.hasArg("alPub");
    prefs.putBool("alLed",alertLedOn);prefs.putBool("alBuzz",alertBuzzOn);prefs.putBool("alVib",alertVibOn);prefs.putBool("alPub",alertPubOn);
    prefs.putBool("showMsg",showMsgOnOLED);
    if(server.hasArg("sessMins")){int sm=server.arg("sessMins").toInt();if(sm>=0&&sm<=60){sessionMinutes=sm;prefs.putInt("sessMins",sm);}}
    prefs.putString("wifiSSID",wifiSSID);prefs.putString("wifiPass",wifiPass);
    prefs.putString("bleName",bleName);prefs.putString("blePin",blePin);
    prefs.putBool("wifiOn",wifiEnabled);prefs.putBool("bleOn",bleEnabled);
    if(server.hasArg("batCapMah")){batCapMah=server.arg("batCapMah").toInt();prefs.putInt("batCapMah",batCapMah);}
    if(server.hasArg("batMinMv")){batMinMv=server.arg("batMinMv").toFloat();prefs.putFloat("batMinMv",batMinMv);}
    if(server.hasArg("batMaxMv")){batMaxMv=server.arg("batMaxMv").toFloat();prefs.putFloat("batMaxMv",batMaxMv);}
    if(server.hasArg("batDivider")){float bd=server.arg("batDivider").toFloat();if(bd>=1.0f&&bd<=12.0f){batDivider=bd;prefs.putFloat("batDivider",batDivider);}}
    batLiFePO4=server.hasArg("batLiFePO4");prefs.putBool("batLiFePO4",batLiFePO4);
    server.sendHeader("Location","/?saved=1");server.send(302,"text/plain","");delay(500);applyMode();
  });
  server.on("/licence",HTTP_POST,[](){
    if(!checkSessionCookie()){server.send(403,"text/plain","Locked");return;}
    if(server.hasArg("key")){
      String k=server.arg("key");k.trim();
      validateAndSaveLicence(k)?server.sendHeader("Location","/?licok=1"):server.sendHeader("Location","/?licfail=1");
    } else server.sendHeader("Location","/");
    server.send(302,"text/plain","");if(oledOn)updateOLED();
  });
  server.on("/status",HTTP_GET,[](){
    if(!deviceUnlocked){server.send(403,"application/json","{\"locked\":true}");return;}
    char buf[512];char nid[12];sprintf(nid,"%08X",getMyNodeId());
    snprintf(buf,sizeof(buf),
      "{\"mac\":\"%s\",\"node_id\":\"%s\",\"pair_code\":\"PL-%s\","
      "\"licensed\":%s,\"bat\":%d,\"charging\":%s,"
      "\"rssi\":%d,\"clients\":%d,"
      "\"lora_rssi\":%d,\"lora_snr\":%.1f,\"lora_ready\":%s,"
      "\"pkt_rx\":%lu,\"pkt_relay\":%lu,"
      "\"contacts\":%d,\"msg_count\":%d,"
      "\"uptime\":\"%s\",\"lifetime\":\"%s\","
      "\"wifi\":%s,\"ble\":%s,\"pub_left\":%d}",
      WiFi.macAddress().c_str(),nid,generatePairingCode().c_str(),
      isLicensed?"true":"false",batPct,isCharging?"true":"false",
      currentRSSI,clientCount,loraRSSI,loraSNR,loraReady?"true":"false",
      packetsReceived,packetsRelayed,countContacts(),messageCount,
      getUptimeString().c_str(),getLifetimeString().c_str(),
      wifiEnabled?"true":"false",bleEnabled?"true":"false",publicQuotaLeft());
    server.send(200,"application/json",buf);
  });
  // Serial config endpoints
  server.on("/wifi-config",HTTP_POST,[](){
    if(!checkSessionCookie()){server.send(403,"text/plain","Locked");return;}
    if(server.hasArg("ssid")){String v=server.arg("ssid");v.trim();if(v.length()>0&&v.length()<=32){wifiSSID=v;prefs.putString("wifiSSID",wifiSSID);}}
    if(server.hasArg("pass")){String v=server.arg("pass");v.trim();if(v.length()>=8){wifiPass=v;prefs.putString("wifiPass",wifiPass);}}
    server.send(200,"text/plain","ok");
  });
}

// =============================================================
//  SECTION 19 — LoRa
// =============================================================
void ICACHE_RAM_ATTR loraISR(){loraRxFlag=true;}
void initLoRa(){
  pinMode(2, OUTPUT);digitalWrite(2, HIGH);
  SPI.begin(LORA_SCK,LORA_MISO,LORA_MOSI,LORA_CS);
  Serial.print("[LoRa] Init SX1262... ");
  int s=radio.begin(LORA_FREQUENCY,LORA_BANDWIDTH,LORA_SF,LORA_CR,LORA_SYNC_WORD,LORA_TX_POWER,LORA_PREAMBLE);
  if(s==RADIOLIB_ERR_NONE){radio.setTCXO(1.8);radio.setDio2AsRfSwitch(true);loraReady=true;Serial.println("OK");radio.setDio1Action(loraISR);radio.startReceive();lastHello=millis()-295000UL;}
  else{loraReady=false;Serial.printf("FAILED %d\n",s);}
}
// TTL byte offset per type (mirrors relayPacket); -1 = no TTL field.
static int ttlOffset(uint8_t* buf,int len){
  switch(buf[0]){
    case PKT_TYPE_MSG_PUB: case PKT_TYPE_MSG_PRIV:
    case PKT_TYPE_ROOM_MSG: case PKT_TYPE_ROOM_INVITE:
    case PKT_TYPE_DELIVERED: case PKT_TYPE_READ:  return len>13 ? 13 : -1;
    case PKT_TYPE_HELLO: case PKT_TYPE_RELAY:      return len>5  ? 5  : -1;
    case PKT_TYPE_REVOKE:                          return len>9  ? 9  : -1;
  }
  return -1;
}
// Exclude the mutable TTL byte so the same message dedups across every hop.
uint32_t packetHash(uint8_t* buf,int len){
  int skip=ttlOffset(buf,len);
  uint32_t h=2166136261UL;
  for(int i=0;i<len;i++){ if(i==skip) continue; h^=buf[i]; h*=16777619UL; }
  return h;
}
bool seenBefore(uint32_t id){for(int i=0;i<SEEN_CACHE_SIZE;i++)if(seenCache[i]==id)return true;return false;}
void markSeen(uint32_t id){seenCache[seenCacheIdx]=id;seenCacheIdx=(seenCacheIdx+1)%SEEN_CACHE_SIZE;}
String loraSignalQuality(){
  if(packetsReceived==0)return "NONE";
  if(loraRSSI>=-100&&loraSNR>=5)return "STRONG";
  if(loraRSSI>=-110&&loraSNR>=0)return "GOOD";
  if(loraRSSI>=-120&&loraSNR>=-5)return "FAIR";
  return "WEAK";
}
void sendHello(){
  if(!loraReady)return;
  String ms=WiFi.macAddress();uint8_t mac[6];
  sscanf(ms.c_str(),"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]);
  uint8_t pkt[42];pkt[0]=PKT_TYPE_HELLO;
  pkt[1]=mac[2];pkt[2]=mac[3];pkt[3]=mac[4];pkt[4]=mac[5];pkt[5]=3;
  uint16_t h=(uint16_t)(uptimeSeconds/3600);pkt[6]=(h>>8)&0xFF;pkt[7]=h&0xFF;
  pkt[8]=(uint8_t)batPct;pkt[9]=isLicensed?0x01:0x00;
  if(cryptoReady)memcpy(&pkt[10],myPublicKey,CURVE25519_KEY_SIZE);else memset(&pkt[10],0,CURVE25519_KEY_SIZE);
  radio.startTransmit(pkt,sizeof(pkt));lastHello=millis();
}
void handleHello(uint8_t* buf,int len){
  if(len<5)return;
  uint32_t src=((uint32_t)buf[1]<<24)|((uint32_t)buf[2]<<16)|((uint32_t)buf[3]<<8)|(uint32_t)buf[4];
  if(src==getMyNodeId())return;
  if(len>=42&&cryptoReady&&isContact(src)){
    uint8_t* tk=&buf[10];bool hk=false;
    for(int i=0;i<CURVE25519_KEY_SIZE;i++)if(tk[i]!=0){hk=true;break;}
    if(hk){uint8_t sk[AES_KEY_SIZE];if(computeSharedSecretFromPubKey(tk,sk))storeSharedKey(src,sk);}
  }
}
void relayPacket(uint8_t* buf,int len){
  if(!loraReady||len<2)return;
  if(len>=5){
    uint32_t origin=((uint32_t)buf[1]<<24)|((uint32_t)buf[2]<<16)|((uint32_t)buf[3]<<8)|(uint32_t)buf[4];
    if(origin==getMyNodeId())return;
  }
  int tb=-1;
  if(buf[0]==PKT_TYPE_MSG_PUB&&len>13)tb=13;
  if(buf[0]==PKT_TYPE_MSG_PRIV&&len>13)tb=13;
  if(buf[0]==PKT_TYPE_ROOM_MSG&&len>13)tb=13;
  if(buf[0]==PKT_TYPE_ROOM_INVITE&&len>13)tb=13;
  if((buf[0]==PKT_TYPE_DELIVERED||buf[0]==PKT_TYPE_READ)&&len>13)tb=13;
  if(buf[0]==PKT_TYPE_HELLO&&len>5)tb=5;
  if(buf[0]==PKT_TYPE_RELAY&&len>5)tb=5;
  if(buf[0]==PKT_TYPE_REVOKE&&len>9)tb=9;
  if(tb>=0){if(buf[tb]==0)return;buf[tb]--;}
  delay(random(20,80));
  if(radio.startTransmit(buf,len)==RADIOLIB_ERR_NONE){packetsRelayed++;}
}
void loopLoRa(){
  if(!loraReady)return;
  if(millis()-lastHello>=300000UL)sendHello();
  if(!loraRxFlag)return;loraRxFlag=false;
  uint8_t buf[256];int len=radio.getPacketLength();
  if(len==0){radio.startReceive();return;}
  if(radio.readData(buf,len)!=RADIOLIB_ERR_NONE){radio.startReceive();return;}
  if(len<2){radio.startReceive();return;}
  loraRSSI=(int)radio.getRSSI();loraSNR=radio.getSNR();
  packetsReceived++;lastLoraRx=millis();
  Serial.printf("[LoRa] RX %db RSSI:%d SNR:%.1f type:0x%02X\n",len,loraRSSI,loraSNR,buf[0]);
  if(len>=5){char ns[12];sprintf(ns,"%02X%02X%02X%02X",buf[1],buf[2],buf[3],buf[4]);lastNodeSeen=String(ns);}
  uint32_t ph=packetHash(buf,len);if(seenBefore(ph)){radio.startReceive();return;}markSeen(ph);
  switch(buf[0]){
    case PKT_TYPE_HELLO:handleHello(buf,len);relayPacket(buf,len);break;
    case PKT_TYPE_MSG_PUB:handleIncomingMessage(buf,len,false);relayPacket(buf,len);break;
    case PKT_TYPE_MSG_PRIV:{
      uint32_t dst=((uint32_t)buf[5]<<24)|((uint32_t)buf[6]<<16)|((uint32_t)buf[7]<<8)|(uint32_t)buf[8];
      if(dst==getMyNodeId())handleIncomingMessage(buf,len,true);else relayPacket(buf,len);break;
    }
    case PKT_TYPE_KEY_REQ:case PKT_TYPE_KEY_ACK:handleKeyExchange(buf,len);break;
    case PKT_TYPE_REVOKE:handleRevocation(buf,len);relayPacket(buf,len);break;
    case PKT_TYPE_PAIR_REQ:{
      uint32_t pSrc=((uint32_t)buf[1]<<24)|((uint32_t)buf[2]<<16)|((uint32_t)buf[3]<<8)|buf[4];
      if(cryptoReady&&len>=45){
        char targetCode[9]={0};for(int i=0;i<8;i++)targetCode[i]=(char)buf[5+i];
        String myCode=generatePairingCode();
        if(myCode==String(targetCode)){
          incomingPair.fromNode=pSrc;memcpy(incomingPair.pubKey,&buf[13],CURVE25519_KEY_SIZE);
          incomingPair.pending=true;incomingPair.receivedAt=millis();
          Serial.printf("[Pair] Incoming request from %08X\n",pSrc);
          char pmsg[32];sprintf(pmsg,"PAIR REQ:%08X",pSrc);storeMessage(pSrc,false,false,pmsg);
          lastOledActivity=millis();wakeOLED();updateOLED();
        }
      }
      break;}
    case PKT_TYPE_PAIR_ACK:{
      uint32_t aSrc=((uint32_t)buf[1]<<24)|((uint32_t)buf[2]<<16)|((uint32_t)buf[3]<<8)|buf[4];
      uint32_t targetId=((uint32_t)buf[5]<<24)|((uint32_t)buf[6]<<16)|((uint32_t)buf[7]<<8)|buf[8];
      if(cryptoReady&&len>=41&&pairReq.pending&&targetId==getMyNodeId()){
        uint8_t theirPubKey[32];memcpy(theirPubKey,&buf[9],CURVE25519_KEY_SIZE);
        uint8_t sharedKey[32];
        if(computeSharedSecretFromPubKey(theirPubKey,sharedKey)){
          addContact(aSrc,sharedKey,pairReq.name.c_str());
          pairReq.accepted=true;pairReq.pending=false;pairReq.nodeId=aSrc;
          lastOledActivity=millis();wakeOLED();updateOLED();
        }
      }
      break;}
    case PKT_TYPE_ROOM_MSG:handleRoomMessage(buf,len);relayPacket(buf,len);break;
    case PKT_TYPE_ROOM_INVITE:{
      uint32_t dst=((uint32_t)buf[5]<<24)|((uint32_t)buf[6]<<16)|((uint32_t)buf[7]<<8)|(uint32_t)buf[8];
      if(dst==getMyNodeId())handleRoomInvite(buf,len);else relayPacket(buf,len);break;
    }
    case PKT_TYPE_DELIVERED:case PKT_TYPE_READ:{
      uint32_t dst=((uint32_t)buf[5]<<24)|((uint32_t)buf[6]<<16)|((uint32_t)buf[7]<<8)|(uint32_t)buf[8];
      if(dst==getMyNodeId())handleAck(buf,len,buf[0]);else relayPacket(buf,len);break;
    }
    case PKT_TYPE_RELAY:relayPacket(buf,len);break;
  }
  radio.startReceive();
}

// =============================================================
//  SECTION 20 — OLED SCREENS
// =============================================================
void drawTick(int x,int y){u8g2.drawLine(x,y+4,x+3,y+8);u8g2.drawLine(x+3,y+8,x+9,y);}
void drawCross(int x,int y){u8g2.drawLine(x,y,x+9,y+8);u8g2.drawLine(x+9,y,x,y+8);}
void drawBatteryIcon(int x,int y,int pct,bool chg){
  u8g2.drawFrame(x,y,18,8);u8g2.drawBox(x+18,y+3,2,2);
  if(chg&&pct<99){
    int af=((chargeFrame%5)+1)*3;if(af>16)af=16;u8g2.drawBox(x+1,y+1,af,6);
    if(chargeFrame%2==0){u8g2.setDrawColor(0);u8g2.drawLine(x+10,y+2,x+8,y+4);u8g2.drawLine(x+8,y+4,x+11,y+4);u8g2.drawLine(x+11,y+4,x+9,y+6);u8g2.setDrawColor(1);}
  } else if(pct>=99){u8g2.drawBox(x+1,y+1,16,6);}
  else{int f=(int)(16.0*pct/100.0);if(f>0)u8g2.drawBox(x+1,y+1,f,6);}
}

void drawScreenMain(){
  u8g2.clearBuffer();
  u8g2.drawXBM(0,0,LOGO_W,LOGO_H,plschat_logo);
  u8g2.setFont(u8g2_font_7x13B_tr);u8g2.drawStr(20,13,"PLSChat");
  u8g2.setFont(u8g2_font_5x7_tr);u8g2.drawStr(0,22,"LICENCE");
  if(isLicensed)drawTick(43,14);else drawCross(43,14);
  // Compact days-left readout to the right of the tick, e.g. "234d"
  if(isLicensed){String dl=getDaysLeftString();if(dl!="N/A")u8g2.drawStr(58,22,dl.c_str());}
  if(settingsMode)u8g2.drawStr(0,31,"MODE: SETTINGS");
  else if(wifiEnabled&&bleEnabled)u8g2.drawStr(0,31,"MODE: WiFi+BT");
  else if(wifiEnabled)u8g2.drawStr(0,31,"MODE: WiFi");
  else u8g2.drawStr(0,31,"MODE: Bluetooth");
  u8g2.drawHLine(0,34,128);
  {char buf[20];sprintf(buf,"NODE: %08X",getMyNodeId());u8g2.drawStr(0,44,buf);}
  char up[16];sprintf(up,"UP: %s",getUptimeString().c_str());u8g2.drawStr(0,55,up);
  drawBatteryIcon(105,37,batPct,isCharging);
  if(lowBatWarning&&batWarningVisible)u8g2.drawStr(82,48,"LOW!");
  else if(isCharging&&batPct<99){u8g2.drawStr(82,44,"CHG");char p[8];sprintf(p,"%d%%",batPct);u8g2.drawStr(82,54,p);}
  else if(batPct>=99)u8g2.drawStr(82,48,"100%");
  else{char p[8];sprintf(p,"%d%%",batPct);u8g2.drawStr(82,48,p);}
  // Show lock status on bottom line when locked
  if(!deviceUnlocked){
    unsigned long d=(millis()/600)%2;
    if(d==0)u8g2.drawStr(0,63,"LOCKED 192.168.4.1");
    else u8g2.drawStr(0,63,"Connect WiFi: unlock");
    u8g2.sendBuffer();return;
  }
  if(!loraReady)u8g2.drawStr(0,63,"LoRa: FAILED");
  else if(packetsReceived==0){
    unsigned long d=(millis()/500)%4;char w[22];
    sprintf(w,"LoRa: Listening%s",d==0?"   ":d==1?".  ":d==2?".. ":"...");u8g2.drawStr(0,63,w);
  } else{char r[28];sprintf(r,"L:%ddB %.1fdB R:%lu",loraRSSI,loraSNR,packetsRelayed);u8g2.drawStr(0,63,r);}
  u8g2.sendBuffer();
}

void drawScreenMessages(){
  u8g2.clearBuffer();u8g2.setFont(u8g2_font_5x7_tr);
  char hdr[28];sprintf(hdr,"CHAT [2/6] C:%d",countContacts());u8g2.drawStr(0,8,hdr);
  u8g2.drawHLine(0,10,128);

  if(!showMsgOnOLED){
    // Messages hidden — show lock icon and count only
    u8g2.setFont(u8g2_font_7x13B_tr);
    u8g2.drawStr(40,32,"Messages");
    u8g2.setFont(u8g2_font_5x7_tr);
    char cnt[24];
    sprintf(cnt,"hidden on device (%d)",messageCount);
    u8g2.drawStr(5,46,cnt);
    u8g2.drawStr(10,58,"View in web UI only");
    if(newMessageFlag){
      // Still show NEW! indicator so user knows to check web UI
      u8g2.drawStr(45,8,"NEW!");
    }
    u8g2.sendBuffer();newMessageFlag=false;
    return;
  }

  if(messageCount==0){
    u8g2.drawStr(0,25,"No messages yet");u8g2.drawStr(0,37,"PUB:hello");
    u8g2.drawStr(0,47,"PRV:NODEID:msg");u8g2.drawStr(0,57,"or use web UI");
  } else {
    int start=max(0,messageCount-4);int yp=20;
    for(int i=start;i<messageCount;i++){
      int idx=(messageHead-messageCount+i+MAX_MESSAGES)%MAX_MESSAGES;
      ChatMessage& m=messageStore[idx];char line[26];
      String who=m.isMe?"Me":getContactName(m.fromNode).substring(0,5);
      sprintf(line,"%s%s:%.14s",who.c_str(),m.isPrivate?"(P)":"",m.text);
      u8g2.drawStr(0,yp,line);yp+=10;
    }
    if(newMessageFlag)u8g2.drawStr(100,8,"NEW!");
  }
  u8g2.sendBuffer();newMessageFlag=false;
}

void drawScreenPairing(){
  u8g2.clearBuffer();u8g2.setFont(u8g2_font_5x7_tr);
  u8g2.drawStr(0,8,"PAIR [3/6]");u8g2.drawHLine(0,10,128);
  if(!cryptoReady){u8g2.drawStr(0,30,"Crypto not ready");u8g2.sendBuffer();return;}
  u8g2.drawStr(0,20,"Your code:");
  String code="PL-"+generatePairingCode();
  u8g2.setFont(u8g2_font_7x13B_tr);u8g2.drawStr(0,34,code.c_str());
  u8g2.setFont(u8g2_font_5x7_tr);
  char nid[14];sprintf(nid,"ID:%08X",getMyNodeId());u8g2.drawStr(0,46,nid);
  char ct[20];sprintf(ct,"Contacts:%d  Lock:ON",countContacts());u8g2.drawStr(0,56,ct);
  u8g2.drawStr(0,63,"Pair via Web UI");
  u8g2.sendBuffer();
}

void drawScreenGraph(){
  u8g2.clearBuffer();u8g2.setFont(u8g2_font_5x7_tr);
  u8g2.drawStr(0,7,"RSSI HISTORY [4/6]");u8g2.drawHLine(0,9,128);
  u8g2.drawStr(0,20,"-90");u8g2.drawStr(0,36,"-110");u8g2.drawStr(0,52,"-130");
  for(int x=18;x<128;x+=3){u8g2.drawPixel(x,14);u8g2.drawPixel(x,30);u8g2.drawPixel(x,46);}
  int tot=rssiHistoryFull?RSSI_HISTORY:rssiIndex;
  for(int i=0;i<tot;i++){
    int idx=rssiHistoryFull?(rssiIndex+i)%RSSI_HISTORY:i;
    int h=constrain((int)((rssiHistory[idx]+140)/60.0*46.0),1,46);
    int x=18+(i*2);if(x<128)u8g2.drawVLine(x,56-h,h);
  }
  if(!loraReady)u8g2.drawStr(0,63,"LoRa FAILED");
  else if(packetsReceived==0)u8g2.drawStr(0,63,"Listening...");
  else{char b[22];sprintf(b,"%ddBm Rx:%lu",loraRSSI,packetsReceived);u8g2.drawStr(0,63,b);}
  u8g2.sendBuffer();
}

void drawScreenDebug(){
  u8g2.clearBuffer();u8g2.setFont(u8g2_font_5x7_tr);
  u8g2.drawStr(0,8,"DEBUG [5/6] " PLSCHAT_VERSION);u8g2.drawHLine(0,10,128);
  char b[32];
  sprintf(b,"MAC:%s",WiFi.macAddress().c_str());u8g2.drawStr(0,18,b);
  sprintf(b,"LIC:%s TIER:%s",isLicensed?"Y":"N",isLicensed?licState.tier.c_str():"-");u8g2.drawStr(0,26,b);
  sprintf(b,"DAYS:%s C:%d MSG:%d",getDaysLeftString().c_str(),countContacts(),messageCount);u8g2.drawStr(0,34,b);
  sprintf(b,"BAT:%d%% %s PIN:%s",batPct,isCharging?"CHG":batPct>=99?"FULL":"BAT",deviceUnlocked?"OK":"LOCK");u8g2.drawStr(0,42,b);
  if(!loraReady)sprintf(b,"LoRa:FAIL");else if(packetsReceived==0)sprintf(b,"LoRa:Listen");
  else sprintf(b,"L:%ddBm Rx:%lu Tx:%lu",loraRSSI,packetsReceived,packetsRelayed);
  u8g2.drawStr(0,50,b);
  sprintf(b,"LIFE:%s",getLifetimeString().c_str());u8g2.drawStr(0,58,b);
  u8g2.sendBuffer();
}

void drawScreenLora(){
  u8g2.clearBuffer();u8g2.setFont(u8g2_font_5x7_tr);
  u8g2.drawStr(0,8,"LoRa INFO [6/6]");u8g2.drawHLine(0,10,128);
  char b[32];
  if(!loraReady){u8g2.drawStr(0,25,"LoRa: INIT FAILED");u8g2.drawStr(0,35,"Check hardware");}
  else if(packetsReceived==0){
    u8g2.drawStr(0,22,"Status: Listening");
    sprintf(b,"Freq: %.1f MHz",LORA_FREQUENCY);u8g2.drawStr(0,32,b);
    sprintf(b,"SF%d BW%.0fkHz",LORA_SF,LORA_BANDWIDTH);u8g2.drawStr(0,42,b);
    u8g2.drawStr(0,52,"Waiting for nodes...");
  } else {
    sprintf(b,"RSSI:%d dBm  %s",loraRSSI,loraSignalQuality().c_str());u8g2.drawStr(0,22,b);
    sprintf(b,"SNR: %.1f dB",loraSNR);u8g2.drawStr(0,32,b);
    sprintf(b,"Rx:%lu  Relay:%lu",packetsReceived,packetsRelayed);u8g2.drawStr(0,42,b);
    if(lastNodeSeen.length()>0){sprintf(b,"Last:%s",lastNodeSeen.c_str());u8g2.drawStr(0,52,b);}
    unsigned long sa=(millis()-lastLoraRx)/1000;
    sprintf(b,sa<60?"Heard:%lus ago":"Heard:%lum ago",sa<60?sa:sa/60);u8g2.drawStr(0,62,b);
  }
  u8g2.sendBuffer();
}

void wakeOLED(){
  if(!oledOn){
    u8g2.setPowerSave(0);  // display on
    oledOn=true;
    lastOledActivity=millis(); // only reset timer when waking from sleep
  }
  // Note: do NOT reset lastOledActivity on every call — that prevents timeout
}

void sleepOLED(){
  if(oledOn){
    u8g2.setPowerSave(1);  // display off — saves ~10mA
    oledOn=false;
  }
}

void updateOLED(){
  wakeOLED();  // any updateOLED call wakes the screen
  switch(currentScreen){
    case SCREEN_MAIN:     drawScreenMain();    break;
    case SCREEN_MESSAGES: drawScreenMessages();break;
    case SCREEN_PAIRING:  drawScreenPairing(); break;
    case SCREEN_GRAPH:    drawScreenGraph();   break;
    case SCREEN_DEBUG:    drawScreenDebug();   break;
    case SCREEN_LORA:     drawScreenLora();    break;
  }
}


// =============================================================
//  SECTION 21 — SETUP
// =============================================================
void setup(){
  Serial.begin(115200);delay(2000);
  Serial.println("\n=== PLSChat " PLSCHAT_VERSION " ===");
  pinMode(WHITE_LED,OUTPUT);digitalWrite(WHITE_LED,LOW);
  pinMode(VEXT_PIN,OUTPUT);digitalWrite(VEXT_PIN,LOW);delay(100);
  pinMode(OLED_RST,OUTPUT);digitalWrite(OLED_RST,LOW);delay(20);digitalWrite(OLED_RST,HIGH);delay(50);
  u8g2.begin();u8g2.setContrast(220);
  pinMode(BTN_PIN,INPUT_PULLUP);
  attachInterrupt(digitalPinToInterrupt(BTN_PIN),btnISR,CHANGE);
  for(int i=0;i<RSSI_HISTORY;i++)rssiHistory[i]=-85;
  for(int i=0;i<SEEN_CACHE_SIZE;i++)seenCache[i]=0;

  u8g2.clearBuffer();
  u8g2.drawXBM(56,2,LOGO_W,LOGO_H,plschat_logo);
  u8g2.setFont(u8g2_font_7x13B_tr);u8g2.drawStr(33,38,"PLSChat");
  u8g2.setFont(u8g2_font_5x7_tr);u8g2.drawStr(20,54,PLSCHAT_VERSION " Starting...");
  u8g2.sendBuffer();delay(300);

  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP("PLSChat-boot","");delay(500);

  prefs.begin("plschat",false);

  if(!prefs.getBool("ssidSet",false)){
    String mac=WiFi.macAddress();
    String suffix=mac.substring(12,14)+mac.substring(15,17);
    suffix.toUpperCase();
    prefs.putString("wifiSSID","PLSChat-"+suffix);
    prefs.putString("bleName","PLSChat-"+suffix);
    prefs.putBool("ssidSet",true);
    Serial.printf("[WiFi] First boot unique SSID: PLSChat-%s\n",suffix.c_str());
  }

  wifiSSID=prefs.getString("wifiSSID",DEFAULT_WIFI_SSID);
  wifiPass=prefs.getString("wifiPass",DEFAULT_WIFI_PASS);
  bleName=prefs.getString("bleName",DEFAULT_BLE_NAME);
  blePin=prefs.getString("blePin",DEFAULT_BLE_PIN);
  wifiEnabled=prefs.getBool("wifiOn",true);
  bleEnabled=prefs.getBool("bleOn",false);
  showMsgOnOLED=prefs.getBool("showMsg",false);
  sessionMinutes=prefs.getInt("sessMins",5);
  batCapMah =(int)prefs.getInt("batCapMah",1000);
  batMinMv  =prefs.getFloat("batMinMv",3000.0f);
  batMaxMv  =prefs.getFloat("batMaxMv",4180.0f);
  batDivider=prefs.getFloat("batDivider",4.9f);
  batLiFePO4=prefs.getBool("batLiFePO4",false);
  alertLoadPrefs();alertInit();
  if(!wifiEnabled&&!bleEnabled)wifiEnabled=true;

  WiFi.softAPdisconnect(true);delay(100);
  WiFi.softAP(wifiSSID.c_str(),wifiPass.c_str());delay(400);
  setupWebServer();server.begin();
  Serial.printf("[WiFi] AP started: %s\n",wifiSSID.c_str());

  u8g2.clearBuffer();
  u8g2.setFont(u8g2_font_7x13B_tr);u8g2.drawStr(15,20,"PLSChat");
  u8g2.setFont(u8g2_font_5x7_tr);
  u8g2.drawStr(20,35,"Connect to WiFi:");
  u8g2.drawStr(5,45,wifiSSID.c_str());
  u8g2.drawStr(5,55,"Then: 192.168.4.1");
  u8g2.drawStr(20,63,"to unlock device");
  u8g2.sendBuffer();

  if(digitalRead(BTN_PIN)==LOW){
    Serial.println("[Security] BTN held at boot — hardware PIN entry");
    deviceUnlocked=bootPinEntry();
    if(!deviceUnlocked){while(true)delay(1000);}
  } else {
    deviceUnlocked=false;
    Serial.println("[Security] Booted — unlock via web UI at 192.168.4.1");
  }

  loadSavedState();
  loadMessages();
  lastSaveTime=lastUptimeTick=lastRSSITime=lastRSSIHistory=lastBatTime=lastOledActivity=millis();

  loadLicence();

  batPct=getBatteryPercent();isCharging=getChargingState();

  initLoRa();

  Serial.println("[Boot] crypto init start");
  initCrypto();
  Serial.println("[Boot] crypto init done");
  loadContacts();
  loadRooms();

  Serial.println("\nReady! Serial commands:");
  Serial.println("  LICENSE:v1|MAC|expiry|tier|sig  apply licence");
  Serial.println("  PUB:message          public broadcast");
  Serial.println("  PRV:NODEID:message   private message");
  Serial.println("  STATUS               full status");
  Serial.println("  CONTACTS             list contacts");
}

// =============================================================
//  SECTION 22 — LOOP
// =============================================================
void loop(){
  unsigned long now=millis();
  if(btnDown&&!btnLongHandled&&(now-btnPressTime>=LONG_PRESS_MS)){
    btnLongHandled=true;btnPressed=false;
    settingsMode?exitSettingsMode():enterSettingsMode();
  }
  if(btnPressed){
    btnPressed=false;alertClearUnread();
    if(!oledOn){lastOledActivity=millis();wakeOLED();updateOLED();}
    else{lastOledActivity=millis();currentScreen=(currentScreen+1)%NUM_SCREENS;updateOLED();}
  }
  if(settingsMode&&(now-settingsModeStart>=SETTINGS_TIMEOUT))exitSettingsMode();
  tickUptime();updateRSSI();periodicSave();loopLoRa();alertLoop();
  if(wifiEnabled)server.handleClient();
  if(oledOn&&(millis()-lastOledActivity>=OLED_TIMEOUT_MS))sleepOLED();
  if(now-lastBatTime>=5000){lastBatTime=now;batPct=getBatteryPercent();isCharging=getChargingState();lowBatWarning=(batPct<=20&&!isCharging);}
  if(isCharging&&batPct<99){if(now-lastChargeAnim>=450){chargeFrame=(chargeFrame+1)%6;lastChargeAnim=now;}}else chargeFrame=0;
  if(lowBatWarning&&now-lastBatFlash>=500){batWarningVisible=!batWarningVisible;lastBatFlash=now;}else batWarningVisible=true;

  if(Serial.available()){
    String cmd=Serial.readStringUntil('\n');cmd.trim();

    // ── Wall-clock sync (browser sends its Date.now()/1000 on connect) ──
    if(cmd.startsWith("TIME:")){
      uint32_t t=(uint32_t)strtoul(cmd.substring(5).c_str(),nullptr,10);
      if(t>1700000000UL){ // sanity check: must look like a real epoch
        timeSyncEpoch=t;timeSyncLifetimeSecs=lifetimeSeconds;timeSynced=true;
        prefs.putUInt("tsEpoch",timeSyncEpoch);prefs.putULong("tsLife",timeSyncLifetimeSecs);
        Serial.println("TIME_OK");
      } else Serial.println("TIME_INVALID");
      return;
    }

    // ── Ed25519 licence install (NEW) ───────────────────────
    if(cmd.startsWith("LICENCE:")||cmd.startsWith("LICENSE:")){
      handleLicenceCommand(cmd);          // verifies Ed25519 sig, stores in NVS
      isLicensed    = licState.valid;
      licenceExpiry = licState.expiry;
      if(oledOn)updateOLED();
      return;
    }

    if(cmd.startsWith("PUB:")){String m=cmd.substring(4);m.trim();if(m.length()>0){if(consumePublicQuota())sendPublicMessage(m);else Serial.println("PUBLIC_CAP_REACHED");}return;}
    if(cmd.startsWith("PRV:")){
      if(!isLicensed){Serial.println("LICENCE_REQUIRED");return;}
      String r=cmd.substring(4);int c=r.indexOf(':');
      if(c>0){uint32_t id=(uint32_t)strtoul(r.substring(0,c).c_str(),nullptr,16);if(id)sendPrivateMessage(id,r.substring(c+1));}
      return;
    }
    if(cmd.startsWith("PAIR:")){
      uint8_t sk[AES_KEY_SIZE];uint32_t id=parsePairingPayload(cmd.substring(5),sk);
      if(id&&id!=getMyNodeId()){if(addContact(id,sk,""))Serial.printf("[Pair] Added %08X\n",id);else Serial.println("[Pair] Failed");}
      else Serial.println("[Pair] Invalid payload");return;
    }
    if(cmd=="ALERT:TEST"){alertStart(ALERT_PRIV,true);Serial.println("ALERT_TEST_OK");return;}
    if(cmd=="MYCODE"||cmd=="mycode"){
      Serial.println("\n=== YOUR PAIRING INFO ===");
      Serial.printf("Node ID:  %08X\n",getMyNodeId());
      Serial.printf("Code:     PL-%s\n",generatePairingCode().c_str());
      Serial.println("Payload:");Serial.println(getPairingPayload());
      Serial.println("=========================\n");return;
    }
    if(cmd.startsWith("WIFI SSID:")){String v=cmd.substring(10);v.trim();if(v.length()>0&&v.length()<=32){wifiSSID=v;prefs.putString("wifiSSID",wifiSSID);Serial.println("WIFI_SSID_OK");}return;}
    if(cmd.startsWith("WIFI PASS:")){String v=cmd.substring(10);v.trim();if(v.length()>=8){wifiPass=v;prefs.putString("wifiPass",wifiPass);Serial.println("WIFI_PASS_OK");}return;}
    if(cmd.startsWith("BT NAME:")){String v=cmd.substring(8);v.trim();if(v.length()>0){bleName=v;prefs.putString("bleName",bleName);Serial.println("BT_NAME_OK");}return;}
    if(cmd.startsWith("BLE PIN:")){String v=cmd.substring(8);v.trim();if(v.length()>=4){blePin=v;prefs.putString("blePin",blePin);Serial.println("BLE_PIN_OK");}return;}
    if(cmd=="WIFI ON") {wifiEnabled=true; prefs.putBool("wifiOn",true);  Serial.println("WIFI_OK"); return;}
    if(cmd=="WIFI OFF"){wifiEnabled=false;prefs.putBool("wifiOn",false); Serial.println("WIFI_OK"); return;}
    if(cmd=="BLE ON")  {bleEnabled=true;  prefs.putBool("bleOn",true);   Serial.println("BLE_OK");  return;}
    if(cmd=="BLE OFF") {bleEnabled=false; prefs.putBool("bleOn",false);  Serial.println("BLE_OK");  return;}
    if(cmd=="APPLY"||cmd=="APPLY CONFIG"){applyMode();Serial.println("CONFIG_OK");return;}
    if(cmd=="GET CONFIG"){Serial.printf("WIFI_SSID:%s\nBT_NAME:%s\nWIFI:%s\nBLE:%s\nCONFIG_OK\n",wifiSSID.c_str(),bleName.c_str(),wifiEnabled?"ON":"OFF",bleEnabled?"ON":"OFF");return;}
    cmd.toUpperCase();
    if(cmd=="CONTACTS"){Serial.printf("Contacts (%d):\n",countContacts());for(int i=0;i<MAX_CONTACTS;i++)if(contacts[i].valid)Serial.printf("  %08X  %s\n",contacts[i].nodeId,contacts[i].name);}
    else if(cmd.startsWith("REMOVE:")){uint32_t id=(uint32_t)strtoul(cmd.substring(7).c_str(),nullptr,16);removeContact(id)?Serial.printf("Removed %08X\n",id):Serial.println("Not found");}
    else if(cmd=="REVOKE"){if(isLicensed)sendRevocation();else Serial.println("LICENCE_REQUIRED");}
    else if(cmd=="WIFI")   {wifiEnabled=true; prefs.putBool("wifiOn",true); applyMode();}
    else if(cmd=="BLE")    {bleEnabled=true;  prefs.putBool("bleOn",true);  applyMode();}
    else if(cmd=="NOWIFI") {wifiEnabled=false;prefs.putBool("wifiOn",false);applyMode();}
    else if(cmd=="NOBLE")  {bleEnabled=false; prefs.putBool("bleOn",false); applyMode();}
    else if(cmd=="SETTINGS")enterSettingsMode();
    else if(cmd=="EXIT")    exitSettingsMode();
    else if(cmd=="STATUS")  printStatus();
    else if(cmd=="HELLO")   sendHello();
    else if(cmd=="CRYPTO")  Serial.printf("[Crypto] NodeID:%08X Contacts:%d\n",getMyNodeId(),countContacts());
  }

  if(now-lastStatusTime>=10000){
    lastStatusTime=now;printStatus();
  }
  static unsigned long lastDraw=0;
  if(now-lastDraw>=500){lastDraw=now;if(oledOn)updateOLED();}
  delay(40);
}

// =============================================================
//  SECTION 23 — PRINT STATUS
// =============================================================
void printStatus(){
  Serial.println("\n=== PLSCHAT_STATUS ===");
  Serial.printf("MAC:%s\nNODE_ID:%08X\n",WiFi.macAddress().c_str(),getMyNodeId());
  Serial.printf("WIFI_SSID:%s\nBT_NAME:%s\n",wifiSSID.c_str(),bleName.c_str());
  Serial.printf("PAIR_CODE:PL-%s\n",generatePairingCode().c_str());
  Serial.printf("LICENSED:%s\nLIC_EXPIRY:%lu\n",isLicensed?"YES":"NO",licenceExpiry);
  Serial.printf("DAYS_LEFT:%s\n",getDaysLeftString().c_str());
  Serial.printf("TIER:%s\n",licState.tier.c_str());
  Serial.printf("LICENCE:%s\n",licState.raw.c_str());
  Serial.printf("UPTIME:%s\nLIFETIME:%s\n",getUptimeString().c_str(),getLifetimeString().c_str());
  Serial.printf("BAT:%d%%\nCHARGING:%s\n",batPct,isCharging?"YES":"NO");
  Serial.printf("LORA_READY:%s\nLORA_RSSI:%d\nLORA_SNR:%.1f\n",loraReady?"YES":"NO",loraRSSI,loraSNR);
  Serial.printf("PKT_RX:%lu\nPKT_RELAY:%lu\n",packetsReceived,packetsRelayed);
  if(packetsReceived>0)Serial.printf("LAST_NODE:%s\nLORA_QUALITY:%s\n",lastNodeSeen.c_str(),loraSignalQuality().c_str());
  Serial.printf("CONTACTS:%d\nMESSAGES:%d\n",countContacts(),messageCount);
  Serial.printf("CRYPTO:%s\nSECURITY:PIN_LOCKED\n",cryptoReady?"READY":"FAILED");
  Serial.printf("WIFI_CLIENTS:%d\nWIFI:%s\nBLE:%s\nFREE_HEAP:%u\n=== END_STATUS ===\n",clientCount,wifiEnabled?"ON":"OFF",bleEnabled?"ON":"OFF",(unsigned)ESP.getFreeHeap());
}
