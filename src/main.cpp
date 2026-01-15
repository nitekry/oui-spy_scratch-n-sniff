/*
 * OUI-Spy Combined Improved Version
 * All modules combined into single file for easy compilation
 * 
 * Improvements:
 * - Thread safety with mutexes
 * - Memory safety (fixed-size arrays, leak prevention)
 * - Error handling on all operations
 * - Input validation and HTML escaping
 * - Configuration namespace
 * - Proper cleanup functions
 */

#include <Arduino.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_task_wdt.h"
#include <WiFi.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <Preferences.h>
#include <NimBLEDevice.h>
#include <vector>
#include <map>
#include <algorithm>

// ================================
// CONFIGURATION CONSTANTS
// ================================
namespace Config {
    // Wi-Fi AP
    static const char* const AP_SSID = "snoopuntothem";
    static const char* const AP_PASS = nullptr;
    
    // Hardware Pins (Xiao ESP32 S3)
    static const uint8_t BUZZER_PIN = 3;
    static const uint8_t LED_PIN = 21;
    static const uint8_t BUZZER_CHANNEL = 3;
    static const uint8_t LEDC_RESOLUTION_BITS = 8;
    
    // Buzzer Settings
    static const uint16_t BUZZER_FREQ = 2000;
    static const uint8_t BUZZER_DUTY = 127;
    static const uint16_t BEEP_DURATION_MS = 200;
    static const uint16_t BEEP_PAUSE_MS = 150;
    
    // Timing Constants
    static const uint32_t WIFI_SCAN_INTERVAL_MS = 3000;
    static const uint32_t WIFI_MODE_CHANGE_DELAY_MS = 100;
    static const uint32_t DETECT_DEBOUNCE_MS = 250;
    static const uint32_t DETECT_PRESENCE_MS = 3000;
    static const uint32_t DETECT_STALE_MS = 12000;
    static const uint32_t FOX_BEEP_DUR_MS = 60;
    static const uint32_t FOX_LOST_TIMEOUT_MS = 4000;
    
    // Task Settings
    static const uint32_t DETECTION_STACK_SIZE = 12288;
    static const uint32_t BASELINE_STACK_SIZE = 12288;
    static const UBaseType_t TASK_PRIORITY = 1;
    static const BaseType_t TASK_CORE = 1;
    
    // BLE Scan Settings
    static const uint16_t BLE_SCAN_INTERVAL = 45;
    static const uint16_t BLE_SCAN_WINDOW = 15;
    static const uint16_t BLE_FAST_SCAN_INTERVAL = 16;
    static const uint16_t BLE_FAST_SCAN_WINDOW = 15;
    
    // RSSI Thresholds
    static const int16_t RSSI_GREEN = -55;
    static const int16_t RSSI_YELLOW = -67;
    static const int16_t RSSI_ORANGE = -75;
    
    // Storage
    static const char* const PREFS_NAMESPACE = "ouispy";
    static const uint16_t MAX_FILTERS = 100;
}

// ================================
// GLOBAL OBJECTS
// ================================
AsyncWebServer server(80);
Preferences prefs;

// Thread Safety
SemaphoreHandle_t detectMutex = nullptr;
SemaphoreHandle_t filtersMutex = nullptr;
SemaphoreHandle_t resultsMutex = nullptr;

// ================================
// ENUMS & STRUCTS
// ================================
enum class BaselineMode { WIFI_ONLY, BLE_ONLY, WIFI_AND_BLE };
using DetectionMode = BaselineMode;

enum class RunMode { STOPPED = 0, DETECT = 1, FOXHUNT = 2 };

struct Observed {
    char name[64];
    char source[8];
    int16_t rssi;
    bool hasRssi;
    
    Observed() : rssi(-127), hasRssi(false) {
        name[0] = '\0';
        source[0] = '\0';
    }
};

struct DetectionState {
    volatile bool running;
    volatile uint32_t lastSeenMs;
    volatile int16_t bestRssi;
    volatile int16_t lastRssi;
    volatile uint32_t lastHitMs;
    volatile bool hitPending;
    
    DetectionState() : running(false), lastSeenMs(0), bestRssi(-127), 
                       lastRssi(-127), lastHitMs(0), hitPending(false) {}
    
    void reset() {
        running = false;
        lastSeenMs = 0;
        bestRssi = -127;
        lastRssi = -127;
        lastHitMs = 0;
        hitPending = false;
    }
};

struct FoxHuntState {
    volatile bool running;
    volatile int16_t rssi;
    volatile bool hasTarget;
    volatile uint32_t lastSeenMs;
    volatile bool firstSessionBeeped;
    volatile bool startBeepsPending;
    bool isBeeping;
    uint32_t beepStartMs;
    
    FoxHuntState() : running(false), rssi(-100), hasTarget(false), 
                     lastSeenMs(0), firstSessionBeeped(false), 
                     startBeepsPending(false), isBeeping(false), beepStartMs(0) {}
    
    void reset() {
        running = false;
        rssi = -100;
        hasTarget = false;
        lastSeenMs = 0;
        firstSessionBeeped = false;
        startBeepsPending = false;
        isBeeping = false;
        beepStartMs = 0;
    }
};

// ================================
// GLOBAL STATE
// ================================
static std::vector<String> filters;
static volatile bool baselineRunning = false;
static volatile bool stealthMode = false;
static volatile RunMode runMode = RunMode::STOPPED;

static DetectionState detectState;
static FoxHuntState foxState;

// Results storage
static std::vector<std::pair<String, Observed>> lastResultsRows;
static String lastResultsHTMLFull;
static String lastResultsCSV;

// ================================
// FORWARD DECLARATIONS
// ================================
void loadFilters();
void saveFilters();
void clearFilters();
bool addFilterIfNew(const String& entry);
void setupWeb();
void buildResultsArtifacts(const std::map<String, Observed>& macMap);
String renderIndexResultsSection();
String buildIndex();
void startBaseline(BaselineMode mode, uint32_t secs);
bool matchesAnyFilter(const String& macNoDelim, std::vector<String>& localCopy);
void detectionTask(void* pv);
void foxHuntTask(void* pv);

// ================================
// UTILITY FUNCTIONS
// ================================

// HTML escaping for security
String htmlEscape(const String& str) {
    String escaped;
    escaped.reserve(str.length() + 10);
    
    for (size_t i = 0; i < str.length(); i++) {
        switch (str[i]) {
            case '&': escaped += "&amp;"; break;
            case '<': escaped += "&lt;"; break;
            case '>': escaped += "&gt;"; break;
            case '"': escaped += "&quot;"; break;
            case '\'': escaped += "&#39;"; break;
            default: escaped += str[i];
        }
    }
    return escaped;
}

// Safe string to upper without delimiters
String toUpperNoDelim(const String &s) {
    String out;
    out.reserve(12);
    
    for (size_t i = 0; i < s.length() && out.length() < 12; ++i) {
        char c = s[i];
        if (c == ':' || c == '-' || c == ' ' || c == '\r' || c == '\n' || c == '\t') 
            continue;
        out += (char)toupper(c);
    }
    return out;
}

// Validate MAC address format
bool isValidMAC(const String& mac) {
    String clean = toUpperNoDelim(mac);
    
    if (clean.length() != 6 && clean.length() != 12) {
        return false;
    }
    
    for (size_t i = 0; i < clean.length(); i++) {
        if (!isxdigit(clean[i])) {
            return false;
        }
    }
    return true;
}

// Format MAC address for display
String macPretty(const String& macNoDelim12) {
    if (macNoDelim12.length() < 12) return macNoDelim12;
    
    String p;
    p.reserve(17);
    for (int i = 0; i < 12; i += 2) {
        if (i) p += ':';
        p += macNoDelim12.substring(i, i + 2);
    }
    return p;
}

// Set best (strongest) RSSI
inline void setBestRssi(Observed &o, int rssiDbm) {
    if (!o.hasRssi || rssiDbm > o.rssi) {
        o.rssi = (int16_t)rssiDbm;
        o.hasRssi = true;
    }
}

// Safe string copy
void safeCopy(char* dest, size_t destSize, const String& src) {
    size_t len = src.length();
    if (len >= destSize) len = destSize - 1;
    memcpy(dest, src.c_str(), len);
    dest[len] = '\0';
}

// ================================
// HARDWARE CONTROL
// ================================
namespace Hardware {
    inline void ledOn() {
        pinMode(Config::LED_PIN, OUTPUT);
        digitalWrite(Config::LED_PIN, LOW);
    }
    
    inline void ledOff() {
        pinMode(Config::LED_PIN, OUTPUT);
        digitalWrite(Config::LED_PIN, HIGH);
    }
    
    void ledFlashOnce(uint16_t ms = 80) {
        ledOn();
        if (xTaskGetSchedulerState() != taskSCHEDULER_NOT_STARTED) {
            vTaskDelay(pdMS_TO_TICKS(ms));
        } else {
            delay(ms);
        }
        ledOff();
    }
    
    void buzzerOn(int freq = Config::BUZZER_FREQ, uint8_t duty = Config::BUZZER_DUTY) {
        pinMode(Config::BUZZER_PIN, OUTPUT);
        ledcAttachPin(Config::BUZZER_PIN, Config::BUZZER_CHANNEL);
        ledcSetup(Config::BUZZER_CHANNEL, freq, Config::LEDC_RESOLUTION_BITS);
        ledcWrite(Config::BUZZER_CHANNEL, duty);
    }
    
    void buzzerOff() {
        ledcWrite(Config::BUZZER_CHANNEL, 0);
    }
    
    void beepOnce(int durMs = Config::BEEP_DURATION_MS, 
                  int freq = Config::BUZZER_FREQ, 
                  uint8_t duty = Config::BUZZER_DUTY) {
        if (stealthMode) {
            ledOn();
            delay(durMs);
            ledOff();
            return;
        }
        buzzerOn(freq, duty);
        ledOn();
        delay(durMs);
        buzzerOff();
        ledOff();
    }
    
    void beepPattern(uint8_t count = 2) {
        for (uint8_t i = 0; i < count; i++) {
            beepOnce();
            if (i + 1 < count) delay(Config::BEEP_PAUSE_MS);
        }
    }
    
    void startupBeep() { beepPattern(2); }
    void baselineDoneBeep() { beepPattern(3); }
    void detectBeep() { beepPattern(1); }
}

// ================================
// RSSI COLOR CODING
// ================================
const char* rssiClass(bool has, int rssi) {
    if (!has) return "rssi-unk";
    if (rssi >= Config::RSSI_GREEN) return "rssi-g";
    if (rssi >= Config::RSSI_YELLOW) return "rssi-y";
    if (rssi >= Config::RSSI_ORANGE) return "rssi-o";
    return "rssi-r";
}

String rssiCellHtml(const Observed& o) {
    if (!o.hasRssi) {
        return String("<span class='rssi rssi-unk'>-</span>");
    }
    return "<span class='rssi " + String(rssiClass(true, o.rssi)) + "'>" + 
           String(o.rssi) + " dBm</span>";
}

// ================================
// FILTER STORAGE & MANAGEMENT
// ================================

void loadFilters() {
    if (xSemaphoreTake(filtersMutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
        Serial.println("[ERROR] Failed to acquire filters mutex for loading");
        return;
    }
    
    filters.clear();
    filters.reserve(50);
    
    if (!prefs.begin(Config::PREFS_NAMESPACE, true)) {
        Serial.println("[ERROR] Failed to open preferences for reading");
        xSemaphoreGive(filtersMutex);
        return;
    }
    
    uint16_t count = prefs.getUShort("count", 0);
    Serial.printf("[STORAGE] Loading %u filters\n", count);
    
    if (count > Config::MAX_FILTERS) {
        Serial.printf("[WARN] Filter count %u exceeds max %u, capping\n", 
                      count, Config::MAX_FILTERS);
        count = Config::MAX_FILTERS;
    }
    
    for (uint16_t i = 0; i < count; i++) {
        char key[8];
        snprintf(key, sizeof(key), "f%u", i);
        
        String val = prefs.getString(key, "");
        if (val.length() > 0 && isValidMAC(val)) {
            filters.push_back(val);
        } else if (val.length() > 0) {
            Serial.printf("[WARN] Skipping invalid filter at index %u: %s\n", 
                          i, val.c_str());
        }
    }
    
    prefs.end();
    xSemaphoreGive(filtersMutex);
    
    Serial.printf("[STORAGE] Loaded %u valid filters\n", (unsigned)filters.size());
}

void saveFilters() {
    if (xSemaphoreTake(filtersMutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
        Serial.println("[ERROR] Failed to acquire filters mutex for saving");
        return;
    }
    
    if (!prefs.begin(Config::PREFS_NAMESPACE, false)) {
        Serial.println("[ERROR] Failed to open preferences for writing");
        xSemaphoreGive(filtersMutex);
        return;
    }
    
    uint16_t count = filters.size();
    if (count > Config::MAX_FILTERS) {
        Serial.printf("[WARN] Truncating filters from %u to %u\n", 
                      count, Config::MAX_FILTERS);
        count = Config::MAX_FILTERS;
    }
    
    if (!prefs.putUShort("count", count)) {
        Serial.println("[ERROR] Failed to write filter count");
        prefs.end();
        xSemaphoreGive(filtersMutex);
        return;
    }
    
    for (uint16_t i = 0; i < count; i++) {
        char key[8];
        snprintf(key, sizeof(key), "f%u", i);
        
        if (!prefs.putString(key, filters[i])) {
            Serial.printf("[ERROR] Failed to write filter %u\n", i);
        }
    }
    
    prefs.end();
    xSemaphoreGive(filtersMutex);
    
    Serial.printf("[STORAGE] Saved %u filters\n", count);
}

void clearFilters() {
    if (xSemaphoreTake(filtersMutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
        Serial.println("[ERROR] Failed to acquire filters mutex for clearing");
        return;
    }
    
    if (!prefs.begin(Config::PREFS_NAMESPACE, false)) {
        Serial.println("[ERROR] Failed to open preferences for clearing");
        xSemaphoreGive(filtersMutex);
        return;
    }
    
    uint16_t count = prefs.getUShort("count", 0);
    for (uint16_t i = 0; i < count; i++) {
        char key[8];
        snprintf(key, sizeof(key), "f%u", i);
        prefs.remove(key);
    }
    
    prefs.putUShort("count", 0);
    prefs.end();
    
    filters.clear();
    xSemaphoreGive(filtersMutex);
    
    Serial.println("[STORAGE] Filters cleared");
}

bool addFilterIfNew(const String& entry) {
    if (!isValidMAC(entry)) {
        Serial.printf("[WARN] Invalid MAC format, not adding: %s\n", entry.c_str());
        return false;
    }
    
    if (xSemaphoreTake(filtersMutex, pdMS_TO_TICKS(1000)) != pdTRUE) {
        Serial.println("[ERROR] Failed to acquire filters mutex for adding");
        return false;
    }
    
    for (size_t i = 0; i < filters.size(); ++i) {
        if (filters[i].equalsIgnoreCase(entry)) {
            xSemaphoreGive(filtersMutex);
            Serial.printf("[INFO] Filter already exists: %s\n", entry.c_str());
            return false;
        }
    }
    
    if (filters.size() >= Config::MAX_FILTERS) {
        xSemaphoreGive(filtersMutex);
        Serial.printf("[ERROR] Maximum filter count (%u) reached\n", Config::MAX_FILTERS);
        return false;
    }
    
    filters.push_back(entry);
    xSemaphoreGive(filtersMutex);
    
    saveFilters();
    Serial.printf("[STORAGE] Added filter: %s\n", entry.c_str());
    return true;
}

bool matchesAnyFilter(const String& macNoDelim, std::vector<String>& localCopy) {
    if (xSemaphoreTake(filtersMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        localCopy = filters;
        xSemaphoreGive(filtersMutex);
    } else {
        return false;
    }
    
    if (localCopy.empty()) return false;
    
    for (size_t i = 0; i < localCopy.size(); ++i) {
        String fNo = toUpperNoDelim(localCopy[i]);
        
        if (fNo.length() == 6) {
            if (macNoDelim.startsWith(fNo)) return true;
        } else if (fNo.length() == 12) {
            if (macNoDelim == fNo) return true;
        }
    }
    
    return false;
}

// ================================
// DETECTION MODE
// ================================

class DetectBLECallbacks : public NimBLEAdvertisedDeviceCallbacks {
public:
    void onResult(NimBLEAdvertisedDevice* dev) override {
        if (!detectState.running || runMode != RunMode::DETECT) return;
        
        String macNo = toUpperNoDelim(String(dev->getAddress().toString().c_str()));
        if (macNo.length() != 12) return;
        
        std::vector<String> localFilters;
        if (!matchesAnyFilter(macNo, localFilters)) return;
        
        int rssi = dev->getRSSI();
        uint32_t now = millis();
        
        if (xSemaphoreTake(detectMutex, pdMS_TO_TICKS(10)) == pdTRUE) {
            detectState.lastSeenMs = now;
            detectState.lastRssi = (int16_t)rssi;
            
            if (rssi > detectState.bestRssi) {
                detectState.bestRssi = (int16_t)rssi;
            }
            
            if (now - detectState.lastHitMs >= Config::DETECT_DEBOUNCE_MS) {
                detectState.lastHitMs = now;
                detectState.hitPending = true;
            }
            
            xSemaphoreGive(detectMutex);
        }
    }
};

static DetectBLECallbacks detectBleCb;

struct DetectParams {
    DetectionMode mode;
    bool stealth;
};

void cleanupDetection() {
    Serial.println("[DETECT] Cleaning up...");
    
    if (NimBLEDevice::getInitialized()) {
        NimBLEScan* scan = NimBLEDevice::getScan();
        if (scan) {
            scan->stop();
        }
        NimBLEDevice::deinit(true);
    }
    
    if (xSemaphoreTake(detectMutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        detectState.reset();
        xSemaphoreGive(detectMutex);
    }
    
    runMode = RunMode::STOPPED;
}

void dropWiFiAP() {
    WiFi.softAPdisconnect(true);
    vTaskDelay(pdMS_TO_TICKS(Config::WIFI_MODE_CHANGE_DELAY_MS));
    WiFi.mode(WIFI_OFF);
    vTaskDelay(pdMS_TO_TICKS(Config::WIFI_MODE_CHANGE_DELAY_MS));
}

void detectionTask(void* pv) {
    DetectParams* pParams = (DetectParams*)pv;
    DetectParams params = *pParams;
    delete pParams;
    
    stealthMode = params.stealth;
    runMode = RunMode::DETECT;
    
    if (xSemaphoreTake(detectMutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        detectState.reset();
        detectState.running = true;
        xSemaphoreGive(detectMutex);
    }
    
    Serial.printf("[DETECT] Starting, mode=%d (0=WiFi,1=BLE,2=Both)\n", (int)params.mode);
    
    dropWiFiAP();
    
    NimBLEScan* bleScan = nullptr;
    
    if (params.mode == DetectionMode::BLE_ONLY || params.mode == DetectionMode::WIFI_AND_BLE) {
        NimBLEDevice::init("detect");
        
        bleScan = NimBLEDevice::getScan();
        if (!bleScan) {
            Serial.println("[ERROR] Failed to get BLE scan object");
            cleanupDetection();
            vTaskDelete(nullptr);
            return;
        }
        
        bleScan->setAdvertisedDeviceCallbacks(&detectBleCb, false);
        bleScan->setActiveScan(true);
        bleScan->setInterval(Config::BLE_SCAN_INTERVAL);
        bleScan->setWindow(Config::BLE_SCAN_WINDOW);
        bleScan->setDuplicateFilter(false);
        
        if (!bleScan->start(0, nullptr, false)) {
            Serial.println("[ERROR] BLE scan start failed");
            cleanupDetection();
            vTaskDelete(nullptr);
            return;
        }
        
        Serial.println("[DETECT] BLE scan active");
    }
    
    if (params.mode == DetectionMode::WIFI_ONLY || params.mode == DetectionMode::WIFI_AND_BLE) {
        WiFi.mode(WIFI_STA);
        WiFi.disconnect(true, true);
        vTaskDelay(pdMS_TO_TICKS(200));
        Serial.println("[DETECT] Wi-Fi scan loop active");
    }
    
    bool wifiScanInProgress = false;
    uint32_t wifiNextScanMs = 0;
    uint32_t lastDetectSignalMs = 0;
    
    for (;;) {
        esp_task_wdt_reset();
        
        bool anyMatch = false;
        
        if (params.mode == DetectionMode::WIFI_ONLY || params.mode == DetectionMode::WIFI_AND_BLE) {
            const uint32_t now = millis();
            
            if (!wifiScanInProgress && now >= wifiNextScanMs) {
                WiFi.scanDelete();
                if (WiFi.scanNetworks(true, true) == WIFI_SCAN_FAILED) {
                    Serial.println("[WARN] Wi-Fi scan failed to start");
                } else {
                    wifiScanInProgress = true;
                }
                wifiNextScanMs = now + Config::WIFI_SCAN_INTERVAL_MS;
            }
            
            int n = WiFi.scanComplete();
            if (wifiScanInProgress && n >= 0) {
                std::vector<String> localFilters;
                
                for (int i = 0; i < n; i++) {
                    String bssidNo = toUpperNoDelim(WiFi.BSSIDstr(i));
                    
                    if (matchesAnyFilter(bssidNo, localFilters)) {
                        Serial.printf("[DETECT Wi-Fi] Match %s SSID:%s RSSI:%d\n",
                                      bssidNo.c_str(), WiFi.SSID(i).c_str(), WiFi.RSSI(i));
                        anyMatch = true;
                        break;
                    }
                }
                
                WiFi.scanDelete();
                wifiScanInProgress = false;
            }
        }
        
        const uint32_t now2 = millis();
        
        bool present = anyMatch;
        if (xSemaphoreTake(detectMutex, pdMS_TO_TICKS(10)) == pdTRUE) {
            if (detectState.lastSeenMs != 0 && 
                (now2 - detectState.lastSeenMs) <= Config::DETECT_STALE_MS) {
                present = true;
            }
            xSemaphoreGive(detectMutex);
        }
        
        if (present && (now2 - lastDetectSignalMs) >= Config::DETECT_PRESENCE_MS) {
            lastDetectSignalMs = now2;
            
            int16_t best = -127;
            if (xSemaphoreTake(detectMutex, pdMS_TO_TICKS(10)) == pdTRUE) {
                best = detectState.bestRssi;
                detectState.bestRssi = -127;
                if (best == -127) best = detectState.lastRssi;
                xSemaphoreGive(detectMutex);
            }
            
            Serial.printf("[DETECT] Presence: RSSI=%d dBm\n", (int)best);
            
            if (stealthMode) {
                Hardware::ledFlashOnce(80);
            } else {
                Hardware::detectBeep();
            }
        }
        
        vTaskDelay(pdMS_TO_TICKS(80));
    }
}

// ================================
// FOX HUNT MODE
// ================================

int calculateBeepIntervalFox(int rssi) {
    if (rssi >= -35) {
        return map(rssi, -35, -25, 80, 25);
    } else if (rssi >= -45) {
        return map(rssi, -45, -35, 140, 80);
    } else if (rssi >= -55) {
        return map(rssi, -55, -45, 250, 140);
    } else if (rssi >= -65) {
        return map(rssi, -65, -55, 450, 250);
    } else if (rssi >= -75) {
        return map(rssi, -75, -65, 900, 450);
    } else if (rssi >= -85) {
        return map(rssi, -85, -75, 1600, 900);
    } else {
        return 2800;
    }
}

void foxBuzzerInit() {
    if (stealthMode) return;
    pinMode(Config::BUZZER_PIN, OUTPUT);
    ledcAttachPin(Config::BUZZER_PIN, Config::BUZZER_CHANNEL);
    ledcSetup(Config::BUZZER_CHANNEL, 1000, Config::LEDC_RESOLUTION_BITS);
    ledcWrite(Config::BUZZER_CHANNEL, 0);
}

void foxBeepOn() {
    if (!stealthMode) {
        ledcWriteTone(Config::BUZZER_CHANNEL, 1000);
        ledcWrite(Config::BUZZER_CHANNEL, Config::BUZZER_DUTY);
    }
    Hardware::ledOn();
}

void foxBeepOff() {
    if (!stealthMode) {
        ledcWrite(Config::BUZZER_CHANNEL, 0);
    }
    Hardware::ledOff();
}

void foxThreeBeeps() {
    for (int i = 0; i < 3; i++) {
        foxBeepOn();
        vTaskDelay(pdMS_TO_TICKS(100));
        foxBeepOff();
        vTaskDelay(pdMS_TO_TICKS(60));
    }
}

void handleFoxProximityBeeping() {
    const uint32_t now = millis();
    
    bool hasTarget = false;
    uint32_t lastSeen = 0;
    int rssi = -100;
    
    if (xSemaphoreTake(detectMutex, pdMS_TO_TICKS(10)) == pdTRUE) {
        hasTarget = foxState.hasTarget;
        lastSeen = foxState.lastSeenMs;
        rssi = foxState.rssi;
        xSemaphoreGive(detectMutex);
    }
    
    if (!hasTarget || (now - lastSeen) > Config::FOX_LOST_TIMEOUT_MS) {
        foxBeepOff();
        foxState.isBeeping = false;
        return;
    }
    
    const int interval = calculateBeepIntervalFox(rssi);
    
    if (rssi >= -25) {
        foxBeepOn();
        foxState.isBeeping = true;
        return;
    }
    
    if (foxState.isBeeping) {
        if (now - foxState.beepStartMs >= Config::FOX_BEEP_DUR_MS) {
            foxBeepOff();
            foxState.isBeeping = false;
        }
    } else {
        if (now - foxState.beepStartMs >= (uint32_t)interval) {
            foxBeepOn();
            foxState.isBeeping = true;
            foxState.beepStartMs = now;
        }
    }
}

class FoxBLECallbacks : public NimBLEAdvertisedDeviceCallbacks {
public:
    void onResult(NimBLEAdvertisedDevice* dev) override {
        if (!foxState.running) return;
        
        String macNo = toUpperNoDelim(String(dev->getAddress().toString().c_str()));
        if (macNo.length() != 12) return;
        
        std::vector<String> localFilters;
        if (!matchesAnyFilter(macNo, localFilters)) return;
        
        const int rssi = dev->getRSSI();
        
        if (xSemaphoreTake(detectMutex, pdMS_TO_TICKS(10)) == pdTRUE) {
            foxState.rssi = rssi;
            foxState.hasTarget = true;
            foxState.lastSeenMs = millis();
            
            if (!foxState.firstSessionBeeped) {
                foxState.firstSessionBeeped = true;
                foxState.startBeepsPending = true;
                Serial.printf("[HUNT] First detect BLE %s RSSI:%d\n", macNo.c_str(), rssi);
            }
            
            xSemaphoreGive(detectMutex);
        }
    }
};

static FoxBLECallbacks foxBleCb;

struct FoxParams {
    DetectionMode mode;
    bool stealth;
};

void foxHuntTask(void* pv) {
    FoxParams* pParams = (FoxParams*)pv;
    FoxParams params = *pParams;
    delete pParams;
    
    stealthMode = params.stealth;
    runMode = RunMode::FOXHUNT;
    
    if (xSemaphoreTake(detectMutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        foxState.reset();
        foxState.running = true;
        detectState.running = true;
        xSemaphoreGive(detectMutex);
    }
    
    Serial.println("[HUNT] Starting (BLE-only, using Detection Filters)");
    
    dropWiFiAP();
    
    NimBLEDevice::init("");
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    
    NimBLEScan* bleScan = NimBLEDevice::getScan();
    if (!bleScan) {
        Serial.println("[ERROR] Failed to get BLE scan object");
        vTaskDelete(nullptr);
        return;
    }
    
    bleScan->setAdvertisedDeviceCallbacks(&foxBleCb, false);
    bleScan->setInterval(Config::BLE_FAST_SCAN_INTERVAL);
    bleScan->setWindow(Config::BLE_FAST_SCAN_WINDOW);
    bleScan->setActiveScan(true);
    bleScan->setDuplicateFilter(false);
    
    if (!bleScan->start(0, nullptr, false)) {
        Serial.println("[ERROR] BLE scan start failed");
        vTaskDelete(nullptr);
        return;
    }
    
    Serial.println("[HUNT] BLE scan active");
    foxBuzzerInit();
    
    for (;;) {
        esp_task_wdt_reset();
        
        if (foxState.startBeepsPending) {
            foxState.startBeepsPending = false;
            foxThreeBeeps();
        }
        
        handleFoxProximityBeeping();
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

// ================================
// BASELINE SCANNING
// ================================

class BaselineBLECollector : public NimBLEAdvertisedDeviceCallbacks {
public:
    std::map<String, Observed> entries;
    SemaphoreHandle_t mutex;
    
    BaselineBLECollector() {
        mutex = xSemaphoreCreateMutex();
    }
    
    ~BaselineBLECollector() {
        if (mutex) {
            vSemaphoreDelete(mutex);
        }
    }
    
    void onResult(NimBLEAdvertisedDevice* dev) override {
        String macNo = toUpperNoDelim(String(dev->getAddress().toString().c_str()));
        if (macNo.length() != 12) return;
        
        if (xSemaphoreTake(mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
            Observed &o = entries[macNo];
            safeCopy(o.source, sizeof(o.source), "BLE");
            setBestRssi(o, dev->getRSSI());
            
            if (dev->haveName()) {
                String nm = String(dev->getName().c_str());
                if (nm.length() > 0) {
                    safeCopy(o.name, sizeof(o.name), nm);
                }
            }
            
            xSemaphoreGive(mutex);
        }
    }
};

struct BaselineParams {
    BaselineMode mode;
    uint32_t secs;
};

void baselineTask(void* pv) {
    BaselineParams* pParams = (BaselineParams*)pv;
    BaselineParams params = *pParams;
    delete pParams;
    
    baselineRunning = true;
    Serial.printf("[BASELINE] Start mode=%d secs=%u\n", (int)params.mode, params.secs);
    
    BaselineBLECollector bleCb;
    NimBLEScan* bleScan = nullptr;
    
    if (params.mode == BaselineMode::BLE_ONLY || params.mode == BaselineMode::WIFI_AND_BLE) {
        NimBLEDevice::init("baseline");
        
        bleScan = NimBLEDevice::getScan();
        if (!bleScan) {
            Serial.println("[ERROR] Failed to get BLE scan object");
            baselineRunning = false;
            NimBLEDevice::deinit(true);
            vTaskDelete(nullptr);
            return;
        }
        
        bleScan->setAdvertisedDeviceCallbacks(&bleCb, false);
        bleScan->setActiveScan(true);
        bleScan->setInterval(Config::BLE_SCAN_INTERVAL);
        bleScan->setWindow(Config::BLE_SCAN_WINDOW);
        
        if (!bleScan->start(0, nullptr, false)) {
            Serial.println("[ERROR] BLE scan start failed");
            baselineRunning = false;
            NimBLEDevice::deinit(true);
            vTaskDelete(nullptr);
            return;
        }
    }
    
    std::map<String, Observed> macMap;
    uint32_t startMs = millis();
    uint32_t durMs = params.secs * 1000UL;
    
    if (params.mode == BaselineMode::WIFI_ONLY || params.mode == BaselineMode::WIFI_AND_BLE) {
        WiFi.mode(WIFI_AP_STA);
        WiFi.disconnect(true, true);
        vTaskDelay(pdMS_TO_TICKS(100));
        
        while (millis() - startMs < durMs) {
            esp_task_wdt_reset();
            
            int n = WiFi.scanNetworks(false, true);
            
            if (n < 0) {
                Serial.printf("[WARN] Wi-Fi scan failed: %d\n", n);
                delay(500);
                continue;
            }
            
            for (int i = 0; i < n; i++) {
                String bssidNo = toUpperNoDelim(WiFi.BSSIDstr(i));
                if (bssidNo.length() != 12) continue;
                
                Observed &o = macMap[bssidNo];
                safeCopy(o.source, sizeof(o.source), "Wi-Fi");
                setBestRssi(o, WiFi.RSSI(i));
                
                String ssid = WiFi.SSID(i);
                if (ssid.length() > 0 && o.name[0] == '\0') {
                    safeCopy(o.name, sizeof(o.name), ssid);
                }
            }
            
            WiFi.scanDelete();
            vTaskDelay(pdMS_TO_TICKS(150));
        }
    } else {
        while (millis() - startMs < durMs) {
            esp_task_wdt_reset();
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
    
    if (bleScan) {
        bleScan->stop();
    }
    
    if (xSemaphoreTake(bleCb.mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        for (auto it = bleCb.entries.begin(); it != bleCb.entries.end(); ++it) {
            const String &mac = it->first;
            const Observed &oBle = it->second;
            
            auto it2 = macMap.find(mac);
            if (it2 == macMap.end()) {
                macMap[mac] = oBle;
            } else {
                if (it2->second.name[0] == '\0' && oBle.name[0] != '\0') {
                    safeCopy(it2->second.name, sizeof(it2->second.name), oBle.name);
                }
                if (oBle.hasRssi) {
                    setBestRssi(it2->second, oBle.rssi);
                }
            }
        }
        xSemaphoreGive(bleCb.mutex);
    }
    
    if (NimBLEDevice::getInitialized()) {
        NimBLEDevice::deinit(true);
    }
    
    buildResultsArtifacts(macMap);
    
    Serial.printf("[BASELINE] Done, entries=%u\n", (unsigned)macMap.size());
    Hardware::baselineDoneBeep();
    
    baselineRunning = false;
    vTaskDelete(nullptr);
}

void startBaseline(BaselineMode mode, uint32_t secs) {
    if (baselineRunning) {
        Serial.println("[BASELINE] Already running");
        return;
    }
    
    if (secs < 5) secs = 5;
    if (secs > 600) secs = 600;
    
    BaselineParams* bp = new BaselineParams{mode, secs};
    
    BaseType_t result = xTaskCreatePinnedToCore(
        baselineTask, 
        "baselineTask", 
        Config::BASELINE_STACK_SIZE, 
        bp, 
        Config::TASK_PRIORITY, 
        NULL, 
        Config::TASK_CORE
    );
    
    if (result != pdPASS) {
        Serial.println("[ERROR] Failed to create baseline task");
        delete bp;
    }
}

void buildResultsArtifacts(const std::map<String, Observed>& macMap) {
    if (xSemaphoreTake(resultsMutex, pdMS_TO_TICKS(2000)) != pdTRUE) {
        Serial.println("[ERROR] Failed to acquire results mutex");
        return;
    }
    
    lastResultsRows.clear();
    lastResultsRows.reserve(macMap.size());
    lastResultsRows.assign(macMap.begin(), macMap.end());
    
    std::sort(
        lastResultsRows.begin(), 
        lastResultsRows.end(),
        [](const std::pair<String, Observed>& a, const std::pair<String, Observed>& b) -> bool {
            int cmp = strcmp(a.second.source, b.second.source);
            if (cmp == 0) return a.first < b.first;
            return cmp < 0;
        }
    );
    
    String csv;
    csv.reserve(2048);
    csv += "MAC,Source,RSSI,Complete Local Name\n";
    
    for (size_t i = 0; i < lastResultsRows.size(); ++i) {
        const String macP = macPretty(lastResultsRows[i].first);
        const char* src = lastResultsRows[i].second.source[0] ? 
                          lastResultsRows[i].second.source : "BLE";
        const char* nm = lastResultsRows[i].second.name[0] ? 
                         lastResultsRows[i].second.name : "UNKNOWN";
        
        String rssiStr = lastResultsRows[i].second.hasRssi ? 
                         String(lastResultsRows[i].second.rssi) : String("");
        
        String escapedName = String(nm);
        escapedName.replace("\"", "\"\"");
        
        csv += "\"" + macP + "\",\"" + String(src) + "\",\"" + rssiStr + 
               "\",\"" + escapedName + "\"\n";
    }
    
    lastResultsCSV = csv;
    
    String html;
    html.reserve(4096);
    
    html += F(
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>Baseline Results</title>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<style>"
        "body{margin:0;padding:24px;background:#0f0f23;color:#e6ffee;"
        "font-family:'Segoe UI',Tahoma,Arial,sans-serif}"
        ".card{max-width:980px;margin:0 auto;background:#1a1f2b;"
        "border:1px solid #22314a;border-radius:14px;"
        "box-shadow:0 10px 28px rgba(0,0,0,.45);padding:22px;overflow:hidden}"
        "h1{margin:0 0 14px 0;font-size:28px;font-weight:700;color:#9be7a6}"
        "table{width:100%;border-collapse:collapse;margin-top:10px;"
        "background:#0f1420;border-radius:10px;overflow:hidden}"
        "th,td{border-bottom:1px solid #26354d;padding:10px 12px;text-align:left}"
        "th{background:#0c111b;color:#9be7a6;font-weight:600}"
        "tr:hover td{background:#11192a}"
        "a.btn{display:inline-block;margin-top:16px;padding:10px 16px;"
        "border-radius:8px;text-decoration:none;background:#1db954;color:#00100a;"
        "font-weight:600;border:1px solid #2fe26c}"
        "a.link{color:#78f0a8;text-decoration:none}"
        "a.btn:hover{filter:brightness(1.05)}"
        ".rssi{display:inline-block;min-width:76px;text-align:center;"
        "padding:4px 8px;border-radius:999px;font-weight:700}"
        ".rssi-unk{background:#2a3344;color:#cbd5e1}"
        ".rssi-g{background:#1db954;color:#00100a}"
        ".rssi-y{background:#f4d03f;color:#1b1400}"
        ".rssi-o{background:#ff9f1a;color:#1f1200}"
        ".rssi-r{background:#ff4d4d;color:#1a0000}"
        "</style></head><body><div class='card'>"
        "<h1>Baseline Results</h1>"
        "<table><tr><th>MAC</th><th>Source</th><th>RSSI</th>"
        "<th>Complete Local Name</th></tr>"
    );
    
    if (lastResultsRows.empty()) {
        html += F("<tr><td colspan='4'>No devices observed.</td></tr>");
    } else {
        for (size_t i = 0; i < lastResultsRows.size(); ++i) {
            const String macP = macPretty(lastResultsRows[i].first);
            const String oui = macP.substring(0, 8);
            const String dev = macP.substring(9);
            const char* src = lastResultsRows[i].second.source[0] ? 
                              lastResultsRows[i].second.source : "BLE";
            const char* nm = lastResultsRows[i].second.name[0] ? 
                             lastResultsRows[i].second.name : "UNKNOWN";
            
            String escapedName = htmlEscape(String(nm));
            
            html += "<tr><td>"
                    "<a class='link' href='/append_filter?v=" + oui + "'>" + oui + "</a>:"
                    "<a class='link' href='/append_filter?v=" + macP + "'>" + dev + "</a>"
                    "</td><td>" + String(src) + "</td><td>" + 
                    rssiCellHtml(lastResultsRows[i].second) + 
                    "</td><td>" + escapedName + "</td></tr>";
        }
    }
    
    html += F(
        "</table>"
        "<div style='margin-top:10px'>"
        "<a class='btn' href='/'>Home</a> "
        "<a class='btn' href='/baseline_results.csv'>Download CSV</a>"
        "</div></div></body></html>"
    );
    
    lastResultsHTMLFull = html;
    xSemaphoreGive(resultsMutex);
}

String renderIndexResultsSection() {
    if (xSemaphoreTake(resultsMutex, pdMS_TO_TICKS(500)) != pdTRUE) {
        return String("<div class='section'><h3>Results temporarily unavailable</h3></div>");
    }
    
    if (lastResultsRows.empty()) {
        xSemaphoreGive(resultsMutex);
        return String(
            "<div class='section'><h3 style='margin-top:0;color:#9be7a6'>Last Results</h3>"
            "<p class='muted'>No baseline run yet.</p></div>"
        );
    }
    
    String html;
    html.reserve(2048);
    
    html += F(
        "<div class='section'><h3 style='margin-top:0;color:#9be7a6'>Last Results</h3>"
        "<p class='muted'>Click the <b>first 3 bytes</b> to add an OUI, "
        "or the <b>last 3 bytes</b> to add the full MAC.</p>"
        "<div class='resultsWrap'><table class='resultsTable'>"
        "<tr><th>MAC</th><th>Source</th><th>RSSI</th><th>Complete Local Name</th></tr>"
    );
    
    for (size_t i = 0; i < lastResultsRows.size(); ++i) {
        const String macP = macPretty(lastResultsRows[i].first);
        const String oui = macP.substring(0, 8);
        const String dev = macP.substring(9);
        const char* src = lastResultsRows[i].second.source[0] ? 
                          lastResultsRows[i].second.source : "BLE";
        const char* nm = lastResultsRows[i].second.name[0] ? 
                         lastResultsRows[i].second.name : "UNKNOWN";
        
        String escapedName = htmlEscape(String(nm));
        
        html += "<tr>"
                "<td>"
                "<a href='/append_filter?v=" + oui + "' style='color:#78f0a8;text-decoration:none'>" + 
                oui + "</a>:"
                "<a href='/append_filter?v=" + macP + "' style='color:#78f0a8;text-decoration:none'>" + 
                dev + "</a>"
                "</td>"
                "<td>" + String(src) + "</td>"
                "<td>" + rssiCellHtml(lastResultsRows[i].second) + "</td>"
                "<td>" + escapedName + "</td>"
                "</tr>";
    }
    
    html += F(
        "</table></div>"
        "<div style='margin-top:10px'>"
        "<a class='btn' href='/baseline_results.csv'>Download Results</a> "
        "<a class='btn' href='/baseline_results'>Open Full Page</a>"
        "</div></div>"
    );
    
    xSemaphoreGive(resultsMutex);
    return html;
}

// ================================
// HTML TEMPLATE & WEB SERVER
// ================================

static const char* INDEX_HTML = R"HTML(
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>OUI-Spy</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    *{box-sizing:border-box}
    body{margin:0;padding:24px;background:#0f0f23;color:#e6ffee;font-family:'Segoe UI',Tahoma,Arial,sans-serif}
    .container{max-width:980px;margin:0 auto;background:#1a1f2b;border:1px solid #22314a;border-radius:14px;
               box-shadow:0 10px 28px rgba(0,0,0,.45);padding:22px;overflow:hidden}
    h1{margin:0 0 8px 0;font-size:30px;font-weight:700;color:#9be7a6}
    .muted{color:#a8cbb5}
    .section{margin:16px 0;padding:16px;border:1px solid #22314a;border-radius:10px;background:#0f1420}
    textarea,input[type=number]{width:100%;max-width:720px;padding:10px;border-radius:8px;border:1px solid #2a405f;
                                background:#09101b;color:#dff6e6;font-family:Consolas,Menlo,monospace}
    textarea{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;}
    label{display:block;margin:6px 0}
    .btn{display:inline-block;border:1px solid #2fe26c;background:#1db954;color:#00100a;
         padding:10px 16px;border-radius:8px;cursor:pointer;text-decoration:none;font-weight:600;margin-right:8px}
    .btn:hover{filter:brightness(1.05)}
    a{color:#78f0a8}
    .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
    .rssi{display:inline-block;min-width:76px;text-align:center;padding:4px 8px;border-radius:999px;font-weight:700}
    .rssi-unk{background:#2a3344;color:#cbd5e1}
    .rssi-g{background:#1db954;color:#00100a}
    .rssi-y{background:#f4d03f;color:#1b1400}
    .rssi-o{background:#ff9f1a;color:#1f1200}
    .rssi-r{background:#ff4d4d;color:#1a0000}
    .resultsWrap{max-height:360px;overflow-y:auto;overflow-x:hidden;border-radius:10px}
    .resultsTable{width:100%;border-collapse:collapse;background:#0f1420;table-layout:fixed}
    .resultsTable th,.resultsTable td{padding:8px;border-bottom:1px solid #26354d;vertical-align:top;word-break:break-word;overflow-wrap:anywhere}
    .resultsTable th{color:#9be7a6;text-align:left}
  </style>
</head>
<body>
  <div class="container">
    <h1>OUI-SPY</h1>
    <p class="muted">Improved version with thread safety and error handling.</p>

    <div class="section">
      <h3 style="margin-top:0;color:#9be7a6">Detection Filters</h3>
      <form method="POST" action="/save">
        <textarea id="filtersTa" name="filters" rows="7" placeholder="AA:BB:CC or AA:BB:CC:11:22:33, one per line">%FILTERS%</textarea><br><br>
        <input class="btn" type="submit" value="Save Filters">
        <button class="btn" formaction="/filters_clear" formmethod="POST" type="submit"
                onclick="return confirm('Clear all detection filters?');">Clear Filters</button>
      </form>
      <p class="muted">OUI = first 3 bytes. Full MAC = 6 bytes. One entry per line. Max %MAX_FILTERS% filters.</p>
    </div>

    <div class="section">
      <h3 style="margin-top:0;color:#9be7a6">Detection</h3>
      <form method="POST" action="/detect_start">
        <div class="row">
          <span class="muted">Status: %RUN_STATUS%</span>
        </div>
        <hr style="border:0;border-top:1px solid #22314a;margin:12px 0">
        <label class="muted">Scan mode:</label>
        <label><input type="radio" name="d_mode" value="wifi" checked> Wi-Fi</label>
        <label><input type="radio" name="d_mode" value="ble"> BLE</label>
        <label><input type="radio" name="d_mode" value="both"> Wi-Fi &amp; BLE</label><br><br>
        <label><input type="checkbox" name="stealth" value="1"> Stealth (LED only)</label><br><br>
        <button class="btn" type="submit">Start Detect (drops AP)</button>
      </form>
      <p class="muted">To stop, power-cycle or reset the device.</p>
    </div>

    <div class="section">
      <h3 style="margin-top:0;color:#9be7a6">Hunt (BLE only)</h3>
      <form method="POST" action="/hunt_start">
        <p class="muted" style="margin-top:0">Uses your saved Detection Filters. Beep rate follows strongest RSSI match.</p>
        <label><input type="checkbox" name="stealth" value="1"> Stealth (LED only)</label><br><br>
        <button class="btn" type="submit">Start Hunt (drops AP)</button>
      </form>
      <p class="muted">Hunt runs BLE-only for stability. To stop, power-cycle or reset.</p>
    </div>

    <div class="section">
      <h3 style="margin-top:0;color:#9be7a6">Baseline Scan</h3>
      <form method="POST" action="/baseline_start">
        <label><input type="radio" name="mode" value="wifi" checked> Wi-Fi</label>
        <label><input type="radio" name="mode" value="ble"> BLE</label>
        <label><input type="radio" name="mode" value="both"> Wi-Fi &amp; BLE</label><br><br>
        <label>Duration (seconds): <input type="number" min="5" max="600" value="60" name="secs" style="width:120px"></label><br><br>
        <button class="btn" type="submit">Start Baseline</button>
        <a class="btn" href="/baseline_results.csv">Download Results</a>
      </form>
      <p class="muted">You'll hear 3 beeps when baseline finishes; results appear below.</p>
    </div>

    %LAST_RESULTS_SECTION%
  </div>
</body>
</html>
)HTML";

String buildIndex() {
    String fl;
    
    if (xSemaphoreTake(filtersMutex, pdMS_TO_TICKS(500)) == pdTRUE) {
        for (size_t i = 0; i < filters.size(); ++i) {
            if (i) fl += "\n";
            fl += filters[i];
        }
        xSemaphoreGive(filtersMutex);
    }
    
    String resultsSection = renderIndexResultsSection();
    
    String status;
    if (runMode == RunMode::DETECT) {
        status = "Detecting (AP down)";
    } else if (runMode == RunMode::FOXHUNT) {
        status = "Hunt (AP down)";
    } else {
        status = "Stopped";
    }
    
    String html = String(INDEX_HTML);
    html.replace("%FILTERS%", fl);
    html.replace("%LAST_RESULTS_SECTION%", resultsSection);
    html.replace("%RUN_STATUS%", status);
    html.replace("%MAX_FILTERS%", String(Config::MAX_FILTERS));
    
    return html;
}

void setupWeb() {
    server.on("/", HTTP_GET, [](AsyncWebServerRequest *req) {
        req->send(200, "text/html", buildIndex());
    });
    
    server.on("/save", HTTP_POST, [](AsyncWebServerRequest *req) {
        if (req->hasParam("filters", true)) {
            String body = req->getParam("filters", true)->value();
            
            if (xSemaphoreTake(filtersMutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
                filters.clear();
                
                int start = 0;
                while (start < body.length() && filters.size() < Config::MAX_FILTERS) {
                    int nl = body.indexOf('\n', start);
                    String line = (nl == -1) ? body.substring(start) : body.substring(start, nl);
                    start = (nl == -1) ? body.length() : nl + 1;
                    
                    line.trim();
                    if (!line.length()) continue;
                    
                    if (isValidMAC(line)) {
                        filters.push_back(line);
                    } else {
                        Serial.printf("[WARN] Skipping invalid filter: %s\n", line.c_str());
                    }
                }
                
                xSemaphoreGive(filtersMutex);
                saveFilters();
            }
        }
        req->redirect("/");
    });
    
    server.on("/filters_clear", HTTP_POST, [](AsyncWebServerRequest *req) {
        clearFilters();
        req->redirect("/");
    });
    
    server.on("/append_filter", HTTP_GET, [](AsyncWebServerRequest *req) {
        if (req->hasParam("v")) {
            String v = req->getParam("v")->value();
            v.trim();
            addFilterIfNew(v);
        }
        req->redirect("/");
    });
    
    server.on("/baseline_start", HTTP_POST, [](AsyncWebServerRequest *req) {
        if (baselineRunning) {
            req->send(200, "text/html",
                "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width, initial-scale=1'>"
                "<style>body{margin:0;padding:24px;background:#0f0f23;color:#e6ffee;font-family:Segoe UI,Tahoma,Arial,sans-serif}"
                ".card{max-width:720px;margin:0 auto;background:#1a1f2b;border:1px solid #22314a;border-radius:14px;padding:22px}</style></head><body>"
                "<div class='card'><h2 style='color:#9be7a6'>Baseline already running</h2>"
                "<p>When it finishes, you'll hear three beeps and results will appear on the home page.</p>"
                "<p><a href='/' style='color:#78f0a8'>Home</a></p></div></body></html>");
            return;
        }
        
        String modeStr = "wifi";
        uint32_t secs = 60;
        
        if (req->hasParam("mode", true)) {
            modeStr = req->getParam("mode", true)->value();
        }
        if (req->hasParam("secs", true)) {
            secs = req->getParam("secs", true)->value().toInt();
        }
        
        BaselineMode mode = BaselineMode::WIFI_ONLY;
        if (modeStr == "ble") mode = BaselineMode::BLE_ONLY;
        if (modeStr == "both") mode = BaselineMode::WIFI_AND_BLE;
        
        startBaseline(mode, secs);
        
        req->send(200, "text/html",
            "<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>"
            "<style>body{margin:0;padding:24px;background:#0f0f23;color:#e6ffee;font-family:Segoe UI,Tahoma,Arial,sans-serif}"
            ".card{max-width:720px;margin:0 auto;background:#1a1f2b;border:1px solid #22314a;border-radius:14px;padding:22px}</style>"
            "</head><body><div class='card'>"
            "<h2 style='color:#9be7a6'>Baseline started</h2>"
            "<p>When baseline completes, you'll hear three beeps and results will appear on the home page.</p>"
            "<p><a href='/' style='color:#78f0a8'>Home</a> &nbsp; <a href='/baseline_results' style='color:#78f0a8'>Open Full Results</a></p>"
            "</div></body></html>");
    });
    
    server.on("/baseline_results", HTTP_GET, [](AsyncWebServerRequest *req) {
        if (xSemaphoreTake(resultsMutex, pdMS_TO_TICKS(500)) == pdTRUE) {
            String html = lastResultsHTMLFull.length() ? lastResultsHTMLFull :
                "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Baseline Results</title></head>"
                "<body style='background:#0f0f23;color:#e6ffee;font-family:Segoe UI,Tahoma,Arial,sans-serif;padding:24px'>"
                "<div style='max-width:720px;margin:0 auto;background:#1a1f2b;border:1px solid #22314a;border-radius:14px;padding:22px'>"
                "<h2 style='color:#9be7a6'>Baseline Results</h2>"
                "<p>No baseline run yet.</p><a href='/' style='color:#78f0a8'>Back</a></div></body></html>";
            xSemaphoreGive(resultsMutex);
            req->send(200, "text/html", html);
        } else {
            req->send(503, "text/plain", "Results temporarily unavailable");
        }
    });
    
    server.on("/baseline_results.csv", HTTP_GET, [](AsyncWebServerRequest *req) {
        String payload;
        
        if (xSemaphoreTake(resultsMutex, pdMS_TO_TICKS(500)) == pdTRUE) {
            payload = lastResultsCSV.length() ? lastResultsCSV : 
                      String("MAC,Source,RSSI,Complete Local Name\n");
            xSemaphoreGive(resultsMutex);
        } else {
            payload = "MAC,Source,RSSI,Complete Local Name\n";
        }
        
        AsyncWebServerResponse *res = req->beginResponse(200, "text/csv", payload);
        res->addHeader("Content-Disposition", "attachment; filename=\"baseline_results.csv\"");
        req->send(res);
    });
    
    server.on("/detect_start", HTTP_POST, [](AsyncWebServerRequest *req) {
        if (detectState.running) {
            req->send(200, "text/html",
                "<!DOCTYPE html><html><body style='background:#0f0f23;color:#e6ffee;font-family:Segoe UI;padding:24px'>"
                "<p>Already running (AP is dropped). Power-cycle to stop.</p></body></html>");
            return;
        }
        
        bool hasFilters = false;
        if (xSemaphoreTake(filtersMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
            hasFilters = !filters.empty();
            xSemaphoreGive(filtersMutex);
        }
        
        if (!hasFilters) {
            req->send(200, "text/html",
                "<!DOCTYPE html><html><body style='background:#0f0f23;color:#e6ffee;font-family:Segoe UI;padding:24px'>"
                "<p>Please add at least one filter (OUI or MAC) before starting detection.</p>"
                "<p><a href='/' style='color:#78f0a8'>Back</a></p></body></html>");
            return;
        }
        
        String modeStr = "wifi";
        if (req->hasParam("d_mode", true)) {
            modeStr = req->getParam("d_mode", true)->value();
        }
        
        bool stealth = req->hasParam("stealth", true);
        
        DetectionMode mode = DetectionMode::WIFI_ONLY;
        if (modeStr == "ble") mode = DetectionMode::BLE_ONLY;
        if (modeStr == "both") mode = DetectionMode::WIFI_AND_BLE;
        
        req->send(200, "text/html",
            "<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>"
            "<style>body{margin:0;padding:24px;background:#0f0f23;color:#e6ffee;font-family:Segoe UI}"
            ".card{max-width:720px;margin:0 auto;background:#1a1f2b;border:1px solid #22314a;border-radius:14px;padding:22px}</style>"
            "</head><body><div class='card'>"
            "<h2 style='color:#9be7a6'>Starting Detection</h2>"
            "<p>The access point will shut down now. Detection will run continuously. Power-cycle to stop.</p>"
            "<p>Close this page.</p>"
            "</div></body></html>");
        
        vTaskDelay(pdMS_TO_TICKS(200));
        
        DetectParams* dp = new DetectParams{mode, stealth};
        BaseType_t result = xTaskCreatePinnedToCore(
            detectionTask, 
            "detectionTask", 
            Config::DETECTION_STACK_SIZE, 
            dp, 
            Config::TASK_PRIORITY, 
            NULL, 
            Config::TASK_CORE
        );
        
        if (result != pdPASS) {
            Serial.println("[ERROR] Failed to create detection task");
            delete dp;
        }
    });
    
    server.on("/hunt_start", HTTP_POST, [](AsyncWebServerRequest *req) {
        if (foxState.running) {
            req->send(200, "text/html",
                "<!DOCTYPE html><html><body style='background:#0f0f23;color:#e6ffee;font-family:Segoe UI;padding:24px'>"
                "<p>Already running (AP is dropped). Power-cycle to stop.</p></body></html>");
            return;
        }
        
        bool hasFilters = false;
        if (xSemaphoreTake(filtersMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
            hasFilters = !filters.empty();
            xSemaphoreGive(filtersMutex);
        }
        
        if (!hasFilters) {
            req->send(200, "text/html",
                "<!DOCTYPE html><html><body style='background:#0f0f23;color:#e6ffee;font-family:Segoe UI;padding:24px'>"
                "<p>Hunt uses your saved Detection Filters. Please add at least one filter first.</p>"
                "<p><a href='/' style='color:#78f0a8'>Back</a></p></body></html>");
            return;
        }
        
        bool stealth = req->hasParam("stealth", true);
        
        req->send(200, "text/html",
            "<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>"
            "<style>body{margin:0;padding:24px;background:#0f0f23;color:#e6ffee;font-family:Segoe UI}"
            ".card{max-width:720px;margin:0 auto;background:#1a1f2b;border:1px solid #22314a;border-radius:14px;padding:22px}</style>"
            "</head><body><div class='card'>"
            "<h2 style='color:#9be7a6'>Starting Hunt (BLE only)</h2>"
            "<p>The access point will shut down now. Hunt will run continuously. Power-cycle to stop.</p>"
            "<p>Close this page.</p>"
            "</div></body></html>");
        
        vTaskDelay(pdMS_TO_TICKS(200));
        
        FoxParams* fp = new FoxParams{DetectionMode::BLE_ONLY, stealth};
        BaseType_t result = xTaskCreatePinnedToCore(
            foxHuntTask, 
            "foxHuntTask", 
            Config::DETECTION_STACK_SIZE, 
            fp, 
            Config::TASK_PRIORITY, 
            NULL, 
            Config::TASK_CORE
        );
        
        if (result != pdPASS) {
            Serial.println("[ERROR] Failed to create fox hunt task");
            delete fp;
        }
    });
    
    server.on("/health", HTTP_GET, [](AsyncWebServerRequest *req) {
        req->send(200, "text/plain", "ok");
    });
    
    server.on("/beep", HTTP_GET, [](AsyncWebServerRequest *req) {
        Hardware::detectBeep();
        req->send(200, "text/plain", "beep");
    });
    
    server.begin();
    Serial.println("[HTTP] Server started");
}

// ================================
// SETUP & LOOP
// ================================

void setup() {
    Serial.begin(115200);
    vTaskDelay(pdMS_TO_TICKS(200));
    Serial.println("\n[BOOT] OUI-Spy (Improved with thread safety & error handling)");
    
    detectMutex = xSemaphoreCreateMutex();
    filtersMutex = xSemaphoreCreateMutex();
    resultsMutex = xSemaphoreCreateMutex();
    
    if (!detectMutex || !filtersMutex || !resultsMutex) {
        Serial.println("[ERROR] Failed to create mutexes!");
        return;
    }
    
    Hardware::ledOff();
    Hardware::startupBeep();
    
    loadFilters();
    Serial.printf("[BOOT] filters=%u\n", (unsigned)filters.size());
    
    WiFi.mode(WIFI_AP);
    bool ok = WiFi.softAP(Config::AP_SSID, Config::AP_PASS);
    Serial.printf("[AP] %s, IP=%s\n", ok ? "started" : "FAILED", 
                  WiFi.softAPIP().toString().c_str());
    
    if (!ok) {
        Serial.println("[ERROR] Failed to start AP!");
    }
    
    setupWeb();
    
    Serial.println("[READY] open http://192.168.4.1/");
}

void loop() {
    static uint32_t lastCheck = 0;
    const uint32_t CHECK_INTERVAL_MS = 250;
    
    uint32_t now = millis();
    if (now - lastCheck >= CHECK_INTERVAL_MS) {
        lastCheck = now;
    }
    
    vTaskDelay(pdMS_TO_TICKS(10));
}
