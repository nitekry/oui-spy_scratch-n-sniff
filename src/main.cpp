/*
 * OUI-Spy Complete Enhanced Version
 * Features:
 * - Thread safety with mutexes
 * - RSSI threshold filtering (-10 to -100 dBm)
 * - BLE payload capture with detailed parsing
 * - Enhanced download options (CSV + detailed TXT report)
 * - Memory-safe payload storage
 */

#include <Arduino.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_task_wdt.h"
#include <WiFi.h>
#include "esp_wifi.h"
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
    static const char* const AP_SSID = "snoopuntothem";
    static const char* const AP_PASS = nullptr;
    
    static const uint8_t BUZZER_PIN = 3;
    static const uint8_t LED_PIN = 21;
    static const uint8_t BUZZER_CHANNEL = 3;
    static const uint8_t LEDC_RESOLUTION_BITS = 8;
    
    static const uint16_t BUZZER_FREQ = 2000;
    static const uint8_t BUZZER_DUTY = 127;
    static const uint16_t BEEP_DURATION_MS = 200;
    static const uint16_t BEEP_PAUSE_MS = 150;
    
    static const uint32_t WIFI_SCAN_INTERVAL_MS = 3000;
    static const uint32_t WIFI_MODE_CHANGE_DELAY_MS = 100;
    static const uint32_t DETECT_DEBOUNCE_MS = 250;
    static const uint32_t DETECT_PRESENCE_MS = 3000;
    static const uint32_t DETECT_STALE_MS = 12000;
    static const uint32_t FOX_BEEP_DUR_MS = 60;
    static const uint32_t FOX_LOST_TIMEOUT_MS = 4000;
    
    static const uint32_t DETECTION_STACK_SIZE = 12288;
    static const uint32_t BASELINE_STACK_SIZE = 16384;  // Increased for payload processing
    static const UBaseType_t TASK_PRIORITY = 1;
    static const BaseType_t TASK_CORE = 1;
    
    static const uint16_t BLE_SCAN_INTERVAL = 45;
    static const uint16_t BLE_SCAN_WINDOW = 15;
    static const uint16_t BLE_FAST_SCAN_INTERVAL = 16;
    static const uint16_t BLE_FAST_SCAN_WINDOW = 15;
    
    static const int16_t RSSI_GREEN = -55;
    static const int16_t RSSI_YELLOW = -67;
    static const int16_t RSSI_ORANGE = -75;
    
    static const char* const PREFS_NAMESPACE = "ouispy";
    static const uint16_t MAX_FILTERS = 100;
    
    // Enhanced baseline settings
    static const uint16_t MAX_PAYLOAD_DEVICES = 50;
    static const uint8_t MAX_PAYLOAD_SIZE = 64;
    static const size_t MAX_PAYLOAD_MEMORY = 10240;
}

// ================================
// GLOBAL OBJECTS
// ================================
AsyncWebServer server(80);
Preferences prefs;

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

// Enhanced struct with Wi-Fi metadata
struct ObservedEnhanced {
    char name[64];
    char source[8];
    int16_t rssi;
    bool hasRssi;
    
    // BLE payload
    bool hasPayload;
    uint8_t payloadData[Config::MAX_PAYLOAD_SIZE];
    uint8_t payloadLength;
    uint8_t addrType;
    
    // Wi-Fi metadata (NEW)
    bool hasWiFiMeta;
    uint8_t channel;
    wifi_auth_mode_t authMode;
    wifi_cipher_type_t pairwiseCipher;
    wifi_cipher_type_t groupCipher;
    bool isHidden;
    
    ObservedEnhanced() : rssi(-127), hasRssi(false), hasPayload(false), 
                         payloadLength(0), addrType(0), hasWiFiMeta(false),
                         channel(0), authMode(WIFI_AUTH_OPEN), 
                         pairwiseCipher(WIFI_CIPHER_TYPE_NONE),
                         groupCipher(WIFI_CIPHER_TYPE_NONE), isHidden(false) {
        name[0] = '\0';
        source[0] = '\0';
        memset(payloadData, 0, Config::MAX_PAYLOAD_SIZE);
    }
};

// Helper function: Get encryption type string
const char* getEncryptionType(wifi_auth_mode_t authMode) {
    switch(authMode) {
        case WIFI_AUTH_OPEN: return "Open";
        case WIFI_AUTH_WEP: return "WEP";
        case WIFI_AUTH_WPA_PSK: return "WPA-PSK";
        case WIFI_AUTH_WPA2_PSK: return "WPA2-PSK";
        case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2-PSK";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-Enterprise";
        case WIFI_AUTH_WPA3_PSK: return "WPA3-PSK";
        case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3-PSK";
        case WIFI_AUTH_WAPI_PSK: return "WAPI-PSK";
        default: return "Unknown";
    }
}

// Helper function: Get cipher type string
const char* getCipherType(wifi_cipher_type_t cipher) {
    switch(cipher) {
        case WIFI_CIPHER_TYPE_NONE: return "None";
        case WIFI_CIPHER_TYPE_WEP40: return "WEP40";
        case WIFI_CIPHER_TYPE_WEP104: return "WEP104";
        case WIFI_CIPHER_TYPE_TKIP: return "TKIP";
        case WIFI_CIPHER_TYPE_CCMP: return "CCMP (AES)";
        case WIFI_CIPHER_TYPE_TKIP_CCMP: return "TKIP/CCMP";
        default: return "Unknown";
    }
}

// Helper function: Get band from channel
const char* getBandFromChannel(uint8_t channel) {
    if (channel >= 1 && channel <= 14) return "2.4 GHz";
    if (channel >= 36 && channel <= 165) return "5 GHz";
    return "Unknown";
}

// Helper function: Check if channel suggests 40MHz width
bool isLikely40MHz(uint8_t channel, uint8_t secondaryChannel) {
    // ESP32 doesn't directly expose this, but we can infer from channel
    // This is a simplified check
    return false; // Would need more detailed scan data
}


// ================================
// STRUCTS & STATE (continued)
// ================================

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

struct BaselineConfig {
    BaselineMode mode;
    uint32_t durationSecs;
    int16_t rssiThreshold;
    bool capturePayload;
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

// Results storage (basic)
static std::vector<std::pair<String, Observed>> lastResultsRows;
static String lastResultsHTMLFull;
static String lastResultsCSV;

// Enhanced results storage
static std::vector<std::pair<String, ObservedEnhanced>> enhancedResultsRows;
static String detailedReportTxt;
static size_t currentPayloadMemory = 0;
static BaselineConfig currentBaselineConfig;

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

// Enhanced baseline functions
void startEnhancedBaseline(BaselineMode mode, uint32_t secs, int16_t rssiThreshold, bool capturePayload);
void buildEnhancedResults(const std::map<String, ObservedEnhanced>& macMap, const BaselineConfig& config);
void enhancedBaselineTask(void* pv);
void captureWiFiMetadata(std::map<String, ObservedEnhanced>& macMap, const BaselineConfig& config, uint32_t startMs, uint32_t durMs);
String generateDeviceReport(const String& mac, const ObservedEnhanced& obs);
String generateWiFiDeviceReport(const String& mac, const ObservedEnhanced& obs);
const char* getCompanyName(uint16_t companyId);
const char* getEncryptionType(wifi_auth_mode_t authMode);
const char* getCipherType(wifi_cipher_type_t cipher);
const char* getBandFromChannel(uint8_t channel);
String parseFlags(uint8_t flags);
String formatHexDump(const uint8_t* data, uint8_t length);
String parseAdStructures(const uint8_t* payload, uint8_t length);

// ================================
// UTILITY FUNCTIONS
// ================================

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

inline void setBestRssi(Observed &o, int rssiDbm) {
    if (!o.hasRssi || rssiDbm > o.rssi) {
        o.rssi = (int16_t)rssiDbm;
        o.hasRssi = true;
    }
}

inline void setBestRssiEnhanced(ObservedEnhanced &o, int rssiDbm) {
    if (!o.hasRssi || rssiDbm > o.rssi) {
        o.rssi = (int16_t)rssiDbm;
        o.hasRssi = true;
    }
}

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

String rssiCellHtmlEnhanced(const ObservedEnhanced& o) {
    if (!o.hasRssi) {
        return String("<span class='rssi rssi-unk'>-</span>");
    }
    return "<span class='rssi " + String(rssiClass(true, o.rssi)) + "'>" + 
           String(o.rssi) + " dBm</span>";
}

// ================================
// ENHANCED PAYLOAD PARSING
// ================================

const char* getCompanyName(uint16_t companyId) {
    switch(companyId) {
        case 0x004C: return "Apple Inc.";
        case 0x0006: return "Microsoft";
        case 0x00E0: return "Google";
        case 0x0075: return "Samsung";
        case 0x0087: return "Garmin";
        case 0x0157: return "Xiaomi";
        case 0x02E5: return "Fitbit";
        case 0x0499: return "Ruuvi Innovations";
        case 0x0059: return "Nordic Semiconductor";
        case 0x00D7: return "Huawei";
        case 0x0171: return "Amazon";
        default: return "Unknown";
    }
}

String parseFlags(uint8_t flags) {
    String result = "";
    if (flags & 0x01) result += "LE Limited, ";
    if (flags & 0x02) result += "LE General, ";
    if (flags & 0x04) result += "No BR/EDR, ";
    if (flags & 0x08) result += "LE+BR/EDR Controller, ";
    if (flags & 0x10) result += "LE+BR/EDR Host, ";
    if (result.length() > 2) result = result.substring(0, result.length() - 2);
    return result.length() ? result : "None";
}

String formatHexDump(const uint8_t* data, uint8_t length) {
    String dump;
    dump.reserve(length * 5 + 100);
    
    dump += "  Offset  Hex                                              ASCII\n";
    dump += "  ------  -----------------------------------------------  ----------------\n";
    
    for (uint8_t i = 0; i < length; i += 16) {
        char line[100];
        snprintf(line, sizeof(line), "  0x%04X  ", i);
        dump += line;
        
        for (uint8_t j = 0; j < 16; j++) {
            if (i + j < length) {
                snprintf(line, sizeof(line), "%02X ", data[i + j]);
                dump += line;
            } else {
                dump += "   ";
            }
            if (j == 7) dump += " ";
        }
        
        dump += " ";
        
        for (uint8_t j = 0; j < 16 && i + j < length; j++) {
            char c = data[i + j];
            dump += (c >= 32 && c <= 126) ? c : '.';
        }
        
        dump += "\n";
    }
    
    return dump;
}

String parseAdStructures(const uint8_t* payload, uint8_t length) {
    String parsed;
    parsed.reserve(512);
    
    parsed += "  Legend:\n";
    parsed += "    Flags | Name | UUIDs | Service Data | Mfg Data | Other\n";
    parsed += "  ----------------\n";
    
    uint8_t pos = 0;
    uint8_t structNum = 1;
    
    while (pos < length) {
        uint8_t len = payload[pos];
        if (len == 0 || pos + len >= length) break;
        
        uint8_t type = payload[pos + 1];
        const uint8_t* data = &payload[pos + 2];
        uint8_t dataLen = len - 1;
        
        char header[50];
        snprintf(header, sizeof(header), "  [%d] Type 0x%02X: ", structNum++, type);
        parsed += header;
        
        switch(type) {
            case 0x01: {
                parsed += "Flags (Length: " + String(dataLen) + " bytes)\n";
                if (dataLen > 0) {
                    parsed += "      Data: 0x" + String(data[0], HEX);
                    parsed += " (" + parseFlags(data[0]) + ")\n";
                }
                break;
            }
            
            case 0x08:
            case 0x09: {
                parsed += (type == 0x08 ? "Shortened" : "Complete");
                parsed += " Local Name (Length: " + String(dataLen) + " bytes)\n";
                parsed += "      Name: \"";
                for (uint8_t i = 0; i < dataLen; i++) {
                    parsed += (char)data[i];
                }
                parsed += "\"\n";
                break;
            }
            
            case 0xFF: {
                parsed += "Manufacturer Data (Length: " + String(dataLen) + " bytes)\n";
                if (dataLen >= 2) {
                    uint16_t companyId = data[0] | (data[1] << 8);
                    parsed += "      Company: 0x" + String(companyId, HEX);
                    parsed += " (" + String(getCompanyName(companyId)) + ")";
                    
                    if (dataLen > 2) {
                        parsed += ", Data: ";
                        for (uint8_t i = 2; i < dataLen && i < 32; i++) {
                            char hex[3];
                            snprintf(hex, sizeof(hex), "%02X", data[i]);
                            parsed += hex;
                        }
                        if (dataLen > 32) parsed += "...";
                    }
                    parsed += "\n";
                }
                break;
            }
            
            case 0x02:
            case 0x03: {
                parsed += (type == 0x02 ? "Incomplete" : "Complete");
                parsed += " 16-bit UUIDs (Length: " + String(dataLen) + " bytes)\n";
                parsed += "      UUIDs: ";
                for (uint8_t i = 0; i < dataLen; i += 2) {
                    if (i > 0) parsed += ", ";
                    uint16_t uuid = data[i] | (data[i+1] << 8);
                    parsed += "0x" + String(uuid, HEX);
                }
                parsed += "\n";
                break;
            }
            
            case 0x16: {
                parsed += "Service Data - 16-bit UUID (Length: " + String(dataLen) + " bytes)\n";
                if (dataLen >= 2) {
                    uint16_t uuid = data[0] | (data[1] << 8);
                    parsed += "      UUID: 0x" + String(uuid, HEX);
                    if (dataLen > 2) {
                        parsed += ", Data: ";
                        for (uint8_t i = 2; i < dataLen && i < 18; i++) {
                            char hex[3];
                            snprintf(hex, sizeof(hex), "%02X", data[i]);
                            parsed += hex;
                        }
                    }
                    parsed += "\n";
                }
                break;
            }
            
            default: {
                parsed += "Unknown Type (Length: " + String(dataLen) + " bytes)\n";
                parsed += "      Raw Data: ";
                for (uint8_t i = 0; i < dataLen && i < 16; i++) {
                    char hex[3];
                    snprintf(hex, sizeof(hex), "%02X", data[i]);
                    parsed += hex;
                    if (i < dataLen - 1) parsed += " ";
                }
                if (dataLen > 16) parsed += "...";
                parsed += "\n";
                break;
            }
        }
        
        pos += len + 1;
    }
    
    return parsed;
}

String generateDeviceReport(const String& mac, const ObservedEnhanced& obs) {
    String report;
    report.reserve(1024);
    
    report += "================================================================================\n";
    report += "[BLE-DEVICE] " + macPretty(mac) + "\n";
    report += "================================================================================\n";
    
    report += "[BASIC-INFO]\n";
    report += "  MAC Address:  " + macPretty(mac) + "\n";
    report += "  RSSI:         " + String(obs.rssi) + " dBm\n";
    report += "  Address Type: " + String(obs.addrType == 0 ? "Public" : "Random") + "\n";
    
    if (obs.name[0] != '\0') {
        report += "  Device Name:  " + String(obs.name) + "\n";
    }
    
    if (obs.hasPayload && obs.payloadLength > 0) {
        report += "[RAW-PAYLOAD]\n";
        report += "  Total Length: " + String(obs.payloadLength) + " bytes\n";
        report += "  Complete Advertisement:\n";
        report += formatHexDump(obs.payloadData, obs.payloadLength);
        
        report += "[AD-STRUCTURES] Advertisement Data Structures:\n";
        report += parseAdStructures(obs.payloadData, obs.payloadLength);
    }
    
    report += "================================================================================\n\n";
    
    return report;
}

// ================================
// WI-FI METADATA CAPTURE & REPORT
// ================================

String generateWiFiDeviceReport(const String& mac, const ObservedEnhanced& obs) {
    String report;
    report.reserve(512);
    
    report += "================================================================================\n";
    report += "[WiFi-AP] " + macPretty(mac) + "\n";
    report += "================================================================================\n";
    
    report += "[BASIC-INFO]\n";
    report += "  MAC Address:  " + macPretty(mac) + "\n";
    report += "  RSSI:         " + String(obs.rssi) + " dBm\n";
    report += "  SSID:         " + String(obs.name[0] ? obs.name : "UNKNOWN/HIDDEN") + "\n";
    
    if (obs.hasWiFiMeta) {
        report += "[NETWORK-INFO]\n";
        report += "  Channel:      " + String(obs.channel) + " (" + String(getBandFromChannel(obs.channel)) + ")\n";
        report += "  Encryption:   " + String(getEncryptionType(obs.authMode)) + "\n";
        
        if (obs.authMode != WIFI_AUTH_OPEN) {
            report += "  Pairwise:     " + String(getCipherType(obs.pairwiseCipher)) + "\n";
            report += "  Group:        " + String(getCipherType(obs.groupCipher)) + "\n";
        }
        
        report += "  Hidden SSID:  " + String(obs.isHidden ? "Yes" : "No") + "\n";
        
        report += "[SIGNAL-ANALYSIS]\n";
        if (obs.rssi >= -50) {
            report += "  Quality:      Excellent (very close)\n";
        } else if (obs.rssi >= -60) {
            report += "  Quality:      Good (close proximity)\n";
        } else if (obs.rssi >= -70) {
            report += "  Quality:      Fair (medium range)\n";
        } else {
            report += "  Quality:      Weak (far away)\n";
        }
        
        if (strcmp(getBandFromChannel(obs.channel), "2.4 GHz") == 0) {
            if (obs.channel == 1 || obs.channel == 6 || obs.channel == 11) {
                report += "  Channel:      Standard (non-overlapping)\n";
            } else {
                report += "  Channel:      Non-standard (may overlap)\n";
            }
        }
        
        report += "[SECURITY-ANALYSIS]\n";
        if (obs.authMode == WIFI_AUTH_OPEN) {
            report += "  Status:       INSECURE - Open network\n";
        } else if (obs.authMode == WIFI_AUTH_WEP) {
            report += "  Status:       WEAK - WEP is outdated\n";
        } else if (obs.authMode == WIFI_AUTH_WPA_PSK) {
            report += "  Status:       WEAK - WPA1 is deprecated\n";
        } else if (obs.authMode == WIFI_AUTH_WPA2_PSK) {
            report += "  Status:       GOOD - WPA2 standard\n";
        } else if (obs.authMode == WIFI_AUTH_WPA3_PSK || obs.authMode == WIFI_AUTH_WPA2_WPA3_PSK) {
            report += "  Status:       EXCELLENT - WPA3 enabled\n";
        } else if (obs.authMode == WIFI_AUTH_WPA2_ENTERPRISE) {
            report += "  Status:       ENTERPRISE - Advanced security\n";
        }
    }
    
    report += "================================================================================\n\n";
    return report;
}

void captureWiFiMetadata(std::map<String, ObservedEnhanced>& macMap,
                         const BaselineConfig& config,
                         uint32_t startMs, uint32_t durMs) {
    WiFi.mode(WIFI_AP_STA);
    WiFi.disconnect(true, true);
    vTaskDelay(pdMS_TO_TICKS(100));

    while (millis() - startMs < durMs) {
        esp_task_wdt_reset();

        int n = WiFi.scanNetworks(false, true); // blocking, show hidden SSIDs

        if (n <= 0) {
            if (n < 0) Serial.printf("[WARN] Wi-Fi scan failed: %d\n", n);
            vTaskDelay(pdMS_TO_TICKS(500));
            continue;
        }

        // Pull detailed records from ESP-IDF BEFORE calling scanDelete()
        uint16_t apCount = (uint16_t)n;
        wifi_ap_record_t* apRecords = new (std::nothrow) wifi_ap_record_t[apCount];
        bool hasDetailedRecords = false;
        if (apRecords) {
            hasDetailedRecords = (esp_wifi_scan_get_ap_records(&apCount, apRecords) == ESP_OK);
            if (!hasDetailedRecords) {
                Serial.println("[WARN] esp_wifi_scan_get_ap_records failed");
            }
        } else {
            Serial.println("[WARN] OOM allocating AP records");
        }

        for (int i = 0; i < n; i++) {
            int rssi = WiFi.RSSI(i);
            if (rssi < config.rssiThreshold) continue;

            String bssidNo = toUpperNoDelim(WiFi.BSSIDstr(i));
            if (bssidNo.length() != 12) continue;

            ObservedEnhanced &o = macMap[bssidNo];
            safeCopy(o.source, sizeof(o.source), "Wi-Fi");
            setBestRssiEnhanced(o, rssi);

            String ssid = WiFi.SSID(i);
            if (ssid.length() > 0 && o.name[0] == '\0') {
                safeCopy(o.name, sizeof(o.name), ssid);
            }

            if (!o.hasWiFiMeta) {
                o.hasWiFiMeta = true;
                o.channel     = WiFi.channel(i);
                o.authMode    = WiFi.encryptionType(i);
                o.isHidden    = (ssid.length() == 0);

                if (hasDetailedRecords && i < (int)apCount) {
                    o.pairwiseCipher = apRecords[i].pairwise_cipher;
                    o.groupCipher    = apRecords[i].group_cipher;
                } else {
                    o.pairwiseCipher = WIFI_CIPHER_TYPE_NONE;
                    o.groupCipher    = WIFI_CIPHER_TYPE_NONE;
                }

                Serial.printf("[WiFi-META] %s Ch:%d Enc:%s Pairwise:%s RSSI:%d\n",
                              bssidNo.c_str(), o.channel,
                              getEncryptionType(o.authMode),
                              getCipherType(o.pairwiseCipher), rssi);
            }
        }

        delete[] apRecords;
        WiFi.scanDelete();
        vTaskDelay(pdMS_TO_TICKS(150));
    }
}

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
// (keeping existing detection code unchanged)
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
// (keeping existing fox hunt code unchanged)
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
// ENHANCED BASELINE SCANNING
// ================================

class EnhancedBLECollector : public NimBLEAdvertisedDeviceCallbacks {
public:
    std::map<String, ObservedEnhanced> entries;
    SemaphoreHandle_t mutex;
    BaselineConfig config;
    size_t payloadMemoryUsed;
    uint16_t devicesWithPayload;
    
    EnhancedBLECollector(const BaselineConfig& cfg) : config(cfg), 
                                                       payloadMemoryUsed(0), 
                                                       devicesWithPayload(0) {
        mutex = xSemaphoreCreateMutex();
    }
    
    ~EnhancedBLECollector() {
        if (mutex) {
            vSemaphoreDelete(mutex);
        }
    }
    
    void onResult(NimBLEAdvertisedDevice* dev) override {
        String macNo = toUpperNoDelim(String(dev->getAddress().toString().c_str()));
        if (macNo.length() != 12) return;
        
        int rssi = dev->getRSSI();
        
        // Apply RSSI threshold filter
        if (rssi < config.rssiThreshold) {
            return;
        }
        
        if (xSemaphoreTake(mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
            ObservedEnhanced &o = entries[macNo];
            safeCopy(o.source, sizeof(o.source), "BLE");
            setBestRssiEnhanced(o, rssi);
            
            o.addrType = dev->getAddressType();
            
            if (dev->haveName()) {
                String nm = String(dev->getName().c_str());
                if (nm.length() > 0) {
                    safeCopy(o.name, sizeof(o.name), nm);
                }
            }
            
            // Capture payload if enabled and memory permits
            if (config.capturePayload && !o.hasPayload) {
                if (devicesWithPayload < Config::MAX_PAYLOAD_DEVICES &&
                    payloadMemoryUsed < Config::MAX_PAYLOAD_MEMORY) {
                    
                    uint8_t* payload = dev->getPayload();
                    uint8_t payloadLen = dev->getPayloadLength();
                    
                    if (payloadLen > 0 && payloadLen <= Config::MAX_PAYLOAD_SIZE) {
                        memcpy(o.payloadData, payload, payloadLen);
                        o.payloadLength = payloadLen;
                        o.hasPayload = true;
                        
                        payloadMemoryUsed += payloadLen;
                        devicesWithPayload++;
                        
                        Serial.printf("[PAYLOAD] Captured %u bytes for %s (Total: %u/%u devices, %u/%u bytes)\n",
                                      payloadLen, macNo.c_str(), devicesWithPayload, 
                                      Config::MAX_PAYLOAD_DEVICES, payloadMemoryUsed, 
                                      Config::MAX_PAYLOAD_MEMORY);
                    }
                } else if (devicesWithPayload >= Config::MAX_PAYLOAD_DEVICES) {
                    // Only log once when we hit the limit
                    static bool limitLogged = false;
                    if (!limitLogged) {
                        Serial.println("[WARN] Payload device limit reached");
                        limitLogged = true;
                    }
                }
            }
            
            xSemaphoreGive(mutex);
        }
    }
};

void enhancedBaselineTask(void* pv) {
    BaselineConfig* pConfig = (BaselineConfig*)pv;
    BaselineConfig config = *pConfig;
    delete pConfig;
    
    currentBaselineConfig = config;
    baselineRunning = true;
    currentPayloadMemory = 0;
    
    Serial.printf("[BASELINE-ENHANCED] Start mode=%d, secs=%u, RSSI>=%d, payload=%s\n", 
                  (int)config.mode, config.durationSecs, config.rssiThreshold,
                  config.capturePayload ? "ON" : "OFF");
    
    EnhancedBLECollector bleCb(config);
    NimBLEScan* bleScan = nullptr;
    
    if (config.mode == BaselineMode::BLE_ONLY || config.mode == BaselineMode::WIFI_AND_BLE) {
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
    
    std::map<String, ObservedEnhanced> macMap;
    uint32_t startMs = millis();
    uint32_t durMs = config.durationSecs * 1000UL;
    
    // WiFi scanning with full metadata capture
    if (config.mode == BaselineMode::WIFI_ONLY || config.mode == BaselineMode::WIFI_AND_BLE) {
        captureWiFiMetadata(macMap, config, startMs, durMs);
    } else {
        while (millis() - startMs < durMs) {
            esp_task_wdt_reset();
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
    
    if (bleScan) {
        bleScan->stop();
    }
    
    // Merge BLE results
    if (xSemaphoreTake(bleCb.mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        for (auto it = bleCb.entries.begin(); it != bleCb.entries.end(); ++it) {
            const String &mac = it->first;
            const ObservedEnhanced &oBle = it->second;
            
            auto it2 = macMap.find(mac);
            if (it2 == macMap.end()) {
                macMap[mac] = oBle;
            } else {
                if (it2->second.name[0] == '\0' && oBle.name[0] != '\0') {
                    safeCopy(it2->second.name, sizeof(it2->second.name), oBle.name);
                }
                if (oBle.hasRssi && oBle.rssi > it2->second.rssi) {
                    it2->second.rssi = oBle.rssi;
                    it2->second.hasRssi = true;
                }
                // Preserve payload from BLE
                if (oBle.hasPayload && !it2->second.hasPayload) {
                    memcpy(it2->second.payloadData, oBle.payloadData, oBle.payloadLength);
                    it2->second.payloadLength = oBle.payloadLength;
                    it2->second.hasPayload = true;
                    it2->second.addrType = oBle.addrType;
                }
            }
        }
        
        currentPayloadMemory = bleCb.payloadMemoryUsed;
        xSemaphoreGive(bleCb.mutex);
    }
    
    if (NimBLEDevice::getInitialized()) {
        NimBLEDevice::deinit(true);
    }
    
    buildEnhancedResults(macMap, config);
    
    Serial.printf("[BASELINE-ENHANCED] Done, %u devices, %u with payloads\n", 
                  (unsigned)macMap.size(), bleCb.devicesWithPayload);
    Hardware::baselineDoneBeep();
    
    baselineRunning = false;
    vTaskDelete(nullptr);
}

void buildEnhancedResults(const std::map<String, ObservedEnhanced>& macMap, const BaselineConfig& config) {
    if (xSemaphoreTake(resultsMutex, pdMS_TO_TICKS(2000)) != pdTRUE) {
        Serial.println("[ERROR] Failed to acquire results mutex");
        return;
    }
    
    enhancedResultsRows.clear();
    enhancedResultsRows.reserve(macMap.size());
    enhancedResultsRows.assign(macMap.begin(), macMap.end());
    
    // Sort by RSSI (strongest first)
    std::sort(
        enhancedResultsRows.begin(), 
        enhancedResultsRows.end(),
        [](const std::pair<String, ObservedEnhanced>& a, const std::pair<String, ObservedEnhanced>& b) -> bool {
            return a.second.rssi > b.second.rssi;
        }
    );

    // ---- Count device types ----
    uint16_t wifiCount = 0;
    uint16_t bleCount = 0;
    uint16_t bleWithPayload = 0;
    for (size_t i = 0; i < enhancedResultsRows.size(); ++i) {
        if (strcmp(enhancedResultsRows[i].second.source, "Wi-Fi") == 0) {
            wifiCount++;
        } else {
            bleCount++;
            if (enhancedResultsRows[i].second.hasPayload) bleWithPayload++;
        }
    }
    
    // ---- Build CSV with Wi-Fi metadata columns ----
    String csv;
    csv.reserve(4096);
    csv += "MAC,Source,RSSI,Channel,Band,Encryption,Pairwise Cipher,Group Cipher,Hidden,Name";
    if (config.capturePayload) {
        csv += ",Has Payload,Payload Length";
    }
    csv += "\n";
    
    for (size_t i = 0; i < enhancedResultsRows.size(); ++i) {
        const String macP = macPretty(enhancedResultsRows[i].first);
        const ObservedEnhanced& obs = enhancedResultsRows[i].second;
        
        csv += "\"" + macP + "\",";
        csv += "\"" + String(obs.source) + "\",";
        csv += obs.hasRssi ? String(obs.rssi) : "";
        csv += ",";
        
        if (obs.hasWiFiMeta) {
            csv += String(obs.channel) + ",";
            csv += "\"" + String(getBandFromChannel(obs.channel)) + "\",";
            csv += "\"" + String(getEncryptionType(obs.authMode)) + "\",";
            csv += "\"" + String(getCipherType(obs.pairwiseCipher)) + "\",";
            csv += "\"" + String(getCipherType(obs.groupCipher)) + "\",";
            csv += obs.isHidden ? "Yes" : "No";
        } else {
            csv += ",,,,,"  ; // 5 empty cells for BLE devices
        }
        csv += ",";
        
        String nm = obs.name[0] ? String(obs.name) : "UNKNOWN";
        nm.replace("\"", "\"\"");
        csv += "\"" + nm + "\"";
        
        if (config.capturePayload) {
            csv += "," + String(obs.hasPayload ? "Yes" : "No");
            csv += "," + String(obs.payloadLength);
        }
        csv += "\n";
    }
    lastResultsCSV = csv;
    
    // ---- Build detailed TXT report ----
    detailedReportTxt = "";
    detailedReportTxt.reserve(8192);
    
    detailedReportTxt += "OUI-SPY ENHANCED BASELINE REPORT\n";
    detailedReportTxt += "Generated: " + String(millis() / 1000) + "s since boot\n";
    detailedReportTxt += "Scan Duration: " + String(config.durationSecs) + " seconds\n";
    detailedReportTxt += "RSSI Threshold: >= " + String(config.rssiThreshold) + " dBm\n";
    detailedReportTxt += "Payload Capture: " + String(config.capturePayload ? "Enabled" : "Disabled") + "\n";
    detailedReportTxt += "Total Devices: " + String(enhancedResultsRows.size()) + "\n";
    detailedReportTxt += "Wi-Fi APs:    " + String(wifiCount) + "\n";
    detailedReportTxt += "BLE Devices:  " + String(bleCount) + " (" + String(bleWithPayload) + " with payloads)\n\n";
    
    if (wifiCount > 0) {
        detailedReportTxt += "################################################################################\n";
        detailedReportTxt += "#                          Wi-Fi ACCESS POINTS                                 #\n";
        detailedReportTxt += "################################################################################\n\n";
        for (size_t i = 0; i < enhancedResultsRows.size(); ++i) {
            if (strcmp(enhancedResultsRows[i].second.source, "Wi-Fi") == 0) {
                detailedReportTxt += generateWiFiDeviceReport(enhancedResultsRows[i].first,
                                                              enhancedResultsRows[i].second);
            }
        }
    }
    
    if (config.capturePayload && bleWithPayload > 0) {
        detailedReportTxt += "################################################################################\n";
        detailedReportTxt += "#                       BLE DEVICES (with payloads)                            #\n";
        detailedReportTxt += "################################################################################\n\n";
        for (size_t i = 0; i < enhancedResultsRows.size(); ++i) {
            if (enhancedResultsRows[i].second.hasPayload) {
                detailedReportTxt += generateDeviceReport(enhancedResultsRows[i].first,
                                                          enhancedResultsRows[i].second);
            }
        }
    } else if (bleCount > 0 && !config.capturePayload) {
        detailedReportTxt += "BLE devices found but payload capture was disabled.\n";
        detailedReportTxt += "Enable payload capture to see detailed BLE advertisement data.\n";
    }
    
    // ---- Build full HTML results page ----
    String html;
    html.reserve(6144);
    
    html += F(
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>Enhanced Baseline Results</title>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<style>"
        "body{margin:0;padding:24px;background:#0f0f23;color:#e6ffee;"
        "font-family:'Segoe UI',Tahoma,Arial,sans-serif}"
        ".card{max-width:1100px;margin:0 auto;background:#1a1f2b;"
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
        "font-weight:600;border:1px solid #2fe26c;margin-right:8px}"
        "a.link{color:#78f0a8;text-decoration:none}"
        "a.btn:hover{filter:brightness(1.05)}"
        ".rssi{display:inline-block;min-width:76px;text-align:center;"
        "padding:4px 8px;border-radius:999px;font-weight:700}"
        ".rssi-unk{background:#2a3344;color:#cbd5e1}"
        ".rssi-g{background:#1db954;color:#00100a}"
        ".rssi-y{background:#f4d03f;color:#1b1400}"
        ".rssi-o{background:#ff9f1a;color:#1f1200}"
        ".rssi-r{background:#ff4d4d;color:#1a0000}"
        ".info{background:#002a1a;border:1px solid #1db954;padding:12px;border-radius:8px;margin:16px 0}"
        ".enc-open{color:#ff4d4d;font-weight:700}"
        ".enc-weak{color:#ff9f1a;font-weight:700}"
        ".enc-good{color:#9be7a6}"
        ".enc-great{color:#1db954;font-weight:700}"
        "</style></head><body><div class='card'>"
        "<h1>Enhanced Baseline Results</h1>"
    );
    
    html += "<div class='info'>";
    html += "<strong>Scan Settings:</strong> ";
    html += "RSSI &gt;= " + String(config.rssiThreshold) + " dBm &nbsp;|&nbsp; ";
    html += "Duration: " + String(config.durationSecs) + "s &nbsp;|&nbsp; ";
    html += "Wi-Fi APs: " + String(wifiCount) + " &nbsp;|&nbsp; ";
    html += "BLE Devices: " + String(bleCount);
    if (config.capturePayload) html += " (" + String(bleWithPayload) + " with payloads)";
    html += "</div>";
    
    // Table header — conditional columns
    html += "<table><tr><th>MAC</th><th>Source</th><th>RSSI</th>"
            "<th>Ch / Band</th><th>Encryption</th><th>Pairwise</th><th>Name</th>";
    if (config.capturePayload) html += "<th>Payload</th>";
    html += "</tr>";
    
    if (enhancedResultsRows.empty()) {
        html += F("<tr><td colspan='8'>No devices observed.</td></tr>");
    } else {
        for (size_t i = 0; i < enhancedResultsRows.size(); ++i) {
            const String macP = macPretty(enhancedResultsRows[i].first);
            const String oui  = macP.substring(0, 8);
            const String dev  = macP.substring(9);
            const ObservedEnhanced& obs = enhancedResultsRows[i].second;
            const char* src = obs.source[0] ? obs.source : "BLE";
            const char* nm  = obs.name[0]   ? obs.name   : "UNKNOWN";
            
            html += "<tr><td>"
                    "<a class='link' href='/append_filter?v=" + oui + "'>" + oui + "</a>:"
                    "<a class='link' href='/append_filter?v=" + macP + "'>" + dev + "</a>"
                    "</td><td>" + String(src) + "</td><td>" +
                    rssiCellHtmlEnhanced(obs) + "</td><td>";
            
            if (obs.hasWiFiMeta) {
                html += String(obs.channel) + " / " + String(getBandFromChannel(obs.channel));
            } else {
                html += "<span style='color:#4a6080'>BLE</span>";
            }
            html += "</td><td>";
            
            if (obs.hasWiFiMeta) {
                // Colour-code encryption
                const char* enc = getEncryptionType(obs.authMode);
                const char* cls = "enc-good";
                if (obs.authMode == WIFI_AUTH_OPEN)    cls = "enc-open";
                else if (obs.authMode == WIFI_AUTH_WEP || obs.authMode == WIFI_AUTH_WPA_PSK) cls = "enc-weak";
                else if (obs.authMode == WIFI_AUTH_WPA3_PSK || obs.authMode == WIFI_AUTH_WPA2_WPA3_PSK) cls = "enc-great";
                html += "<span class='" + String(cls) + "'>" + String(enc) + "</span>";
            } else {
                html += "-";
            }
            html += "</td><td>";
            
            if (obs.hasWiFiMeta && obs.authMode != WIFI_AUTH_OPEN) {
                html += String(getCipherType(obs.pairwiseCipher));
            } else {
                html += "-";
            }
            html += "</td><td>" + htmlEscape(String(nm)) + "</td>";
            
            if (config.capturePayload) {
                html += obs.hasPayload
                    ? "<td>" + String(obs.payloadLength) + "B</td>"
                    : "<td>-</td>";
            }
            html += "</tr>";
        }
    }
    
    html += F("</table><div style='margin-top:10px'>"
              "<a class='btn' href='/'>Home</a> "
              "<a class='btn' href='/baseline_results.csv'>Download CSV</a>");
    
    // Show detailed report link whenever there is Wi-Fi OR BLE payload data
    if (wifiCount > 0 || (config.capturePayload && bleWithPayload > 0)) {
        html += F(" <a class='btn' href='/baseline_results_detailed.txt'>Download Detailed Report</a>");
    }
    
    html += F("</div></div></body></html>");
    lastResultsHTMLFull = html;
    
    xSemaphoreGive(resultsMutex);
}

void startEnhancedBaseline(BaselineMode mode, uint32_t secs, int16_t rssiThreshold, bool capturePayload) {
    if (baselineRunning) {
        Serial.println("[BASELINE] Already running");
        return;
    }
    
    if (secs < 5) secs = 5;
    if (secs > 600) secs = 600;
    if (rssiThreshold < -100) rssiThreshold = -100;
    if (rssiThreshold > -10) rssiThreshold = -10;
    
    BaselineConfig* config = new BaselineConfig{mode, secs, rssiThreshold, capturePayload};
    
    BaseType_t result = xTaskCreatePinnedToCore(
        enhancedBaselineTask, 
        "baselineTask", 
        Config::BASELINE_STACK_SIZE,
        config, 
        Config::TASK_PRIORITY, 
        NULL, 
        Config::TASK_CORE
    );
    
    if (result != pdPASS) {
        Serial.println("[ERROR] Failed to create baseline task");
        delete config;
    }
}

// ================================
// ENHANCED WEB INTERFACE
// ================================

static const char* INDEX_HTML = R"HTML(
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>OUI-Spy Enhanced</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    *{box-sizing:border-box}
    body{margin:0;padding:24px;background:#0f0f23;color:#e6ffee;font-family:'Segoe UI',Tahoma,Arial,sans-serif}
    .container{max-width:980px;margin:0 auto;background:#1a1f2b;border:1px solid #22314a;border-radius:14px;
               box-shadow:0 10px 28px rgba(0,0,0,.45);padding:22px;overflow:hidden}
    h1{margin:0 0 8px 0;font-size:30px;font-weight:700;color:#9be7a6}
    .muted{color:#a8cbb5;font-size:14px}
    .section{margin:16px 0;padding:16px;border:1px solid #22314a;border-radius:10px;background:#0f1420}
    textarea,input[type=number],input[type=range]{width:100%;max-width:720px;padding:10px;border-radius:8px;border:1px solid #2a405f;
                                background:#09101b;color:#dff6e6;font-family:Consolas,Menlo,monospace}
    textarea{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;}
    label{display:block;margin:6px 0}
    .btn{display:inline-block;border:1px solid #2fe26c;background:#1db954;color:#00100a;
         padding:10px 16px;border-radius:8px;cursor:pointer;text-decoration:none;font-weight:600;margin:4px}
    .btn:hover{filter:brightness(1.05)}
    a{color:#78f0a8}
    .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
    .slider-container{display:flex;align-items:center;gap:12px;margin:10px 0}
    .slider{flex:1;max-width:400px}
    .slider-value{min-width:80px;font-weight:600;color:#9be7a6;font-size:16px}
    .warning-box{background:#3d2a00;border:1px solid #f4d03f;padding:12px;border-radius:8px;margin:10px 0}
    .info-box{background:#002a1a;border:1px solid #1db954;padding:12px;border-radius:8px;margin:10px 0}
  </style>
  <script>
    function updateRssiValue(val) {
      document.getElementById('rssiValue').textContent = val + ' dBm';
    }
    
    function togglePayloadWarning() {
      const checkbox = document.getElementById('capturePayload');
      const warning = document.getElementById('payloadWarning');
      warning.style.display = checkbox.checked ? 'block' : 'none';
    }
    
    async function updateMemoryStatus() {
      try {
        const res = await fetch('/memory_status');
        const data = await res.json();
        document.getElementById('memStatus').innerHTML = 
          `Free Heap: ${(data.free_heap/1024).toFixed(1)}KB | ` +
          `Payload Memory: ${data.payload_memory}/${data.max_payload_memory} bytes | ` +
          `Max Devices: ${data.max_devices}`;
      } catch(e) {}
    }
    
    setInterval(updateMemoryStatus, 5000);
    window.onload = updateMemoryStatus;
  </script>
</head>
<body>
  <div class="container">
    <h1>OUI-SPY ENHANCED</h1>
    <p class="muted">Advanced baseline scanning with RSSI filtering and payload capture.</p>
    <div class="muted" id="memStatus" style="margin-top:8px">Loading memory status...</div>

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
      <h3 style="margin-top:0;color:#9be7a6">Enhanced Baseline Scan</h3>
      <form method="POST" action="/baseline_start">
        <label class="muted" style="margin-bottom:8px">Scan Mode:</label>
        <label><input type="radio" name="mode" value="wifi" checked> Wi-Fi</label>
        <label><input type="radio" name="mode" value="ble"> BLE</label>
        <label><input type="radio" name="mode" value="both"> Wi-Fi &amp; BLE</label>
        
        <br><br>
        <label>Duration (seconds): <input type="number" min="5" max="600" value="60" name="secs" style="width:120px"></label>
        
        <br><br>
        <label class="muted">RSSI Threshold (filter nearby devices):</label>
        <div class="slider-container">
          <span class="muted" style="min-width:60px">Weak</span>
          <input type="range" name="rssi_threshold" class="slider" min="-100" max="-10" value="-100" 
                 oninput="updateRssiValue(this.value)">
          <span class="muted" style="min-width:60px">Strong</span>
          <span class="slider-value" id="rssiValue">-100 dBm</span>
        </div>
        <p class="muted">Only scan devices with RSSI >= selected value. -100 = capture all, -50 = nearby only</p>
        
        <div class="info-box">
          <label>
            <input type="checkbox" name="capture_payload" id="capturePayload" onchange="togglePayloadWarning()"> 
            <strong>Capture BLE Payloads (Advertisement Data)</strong>
          </label>
          <p class="muted" style="margin:8px 0 0 24px">
            Captures raw BLE advertisement data including manufacturer info, UUIDs, and service data.
            Useful for device fingerprinting and analysis.
          </p>
        </div>
        
        <div class="warning-box" id="payloadWarning" style="display:none">
          <strong>⚠️ Memory Warning</strong>
          <p class="muted" style="margin:4px 0 0 0">
            Payload capture is memory-intensive. Limited to 50 devices or 10KB total.
            Long scans in crowded areas may hit limits.
          </p>
        </div>
        
        <br>
        <div class="row">
          <button class="btn" type="submit">Start Enhanced Baseline</button>
          <a class="btn" href="/baseline_results.csv">Download CSV</a>
          <a class="btn" href="/baseline_results_detailed.txt">Download Detailed Report</a>
        </div>
      </form>
      <p class="muted">You'll hear 3 beeps when baseline finishes; results appear below.</p>
    </div>

    <div class="section">
      <h3 style="margin-top:0;color:#9be7a6">Detection Mode</h3>
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

    %LAST_RESULTS_SECTION%
  </div>
</body>
</html>
)HTML";

String renderIndexResultsSection() {
    if (xSemaphoreTake(resultsMutex, pdMS_TO_TICKS(500)) != pdTRUE) {
        return String("<div class='section'><h3>Results temporarily unavailable</h3></div>");
    }
    
    if (enhancedResultsRows.empty()) {
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
        "<div style='max-height:360px;overflow-y:auto;overflow-x:hidden;border-radius:10px'>"
        "<table style='width:100%;border-collapse:collapse;background:#0f1420;table-layout:fixed'>"
        "<tr style='color:#9be7a6'><th style='padding:8px'>MAC</th><th style='padding:8px'>Src</th>"
        "<th style='padding:8px'>RSSI</th><th style='padding:8px'>Ch/Band</th>"
        "<th style='padding:8px'>Encryption</th><th style='padding:8px'>Name</th>"
    );
    
    if (currentBaselineConfig.capturePayload) {
        html += "<th style='padding:8px'>Payload</th>";
    }
    
    html += "</tr>";
    
    for (size_t i = 0; i < enhancedResultsRows.size() && i < 50; ++i) {
        const String macP = macPretty(enhancedResultsRows[i].first);
        const String oui = macP.substring(0, 8);
        const String dev = macP.substring(9);
        const char* src = enhancedResultsRows[i].second.source[0] ? 
                          enhancedResultsRows[i].second.source : "BLE";
        const char* nm = enhancedResultsRows[i].second.name[0] ? 
                         enhancedResultsRows[i].second.name : "UNKNOWN";
        
        String escapedName = htmlEscape(String(nm));
        
        html += "<tr style='border-bottom:1px solid #26354d'>"
                "<td style='padding:8px;word-break:break-word'>"
                "<a href='/append_filter?v=" + oui + "' style='color:#78f0a8;text-decoration:none'>" + 
                oui + "</a>:"
                "<a href='/append_filter?v=" + macP + "' style='color:#78f0a8;text-decoration:none'>" + 
                dev + "</a>"
                "</td>"
                "<td style='padding:8px'>" + String(src) + "</td>"
                "<td style='padding:8px'>" + rssiCellHtmlEnhanced(enhancedResultsRows[i].second) + "</td>";
        
        const ObservedEnhanced& obs = enhancedResultsRows[i].second;
        if (obs.hasWiFiMeta) {
            html += "<td style='padding:8px'>" + String(obs.channel) + "/" + 
                    String(getBandFromChannel(obs.channel)) + "</td>";
            html += "<td style='padding:8px'>" + String(getEncryptionType(obs.authMode)) + "</td>";
        } else {
            html += "<td style='padding:8px;color:#4a6080'>-</td>"
                    "<td style='padding:8px;color:#4a6080'>BLE</td>";
        }
        
        html += "<td style='padding:8px'>" + escapedName + "</td>";
        
        if (currentBaselineConfig.capturePayload) {
            if (enhancedResultsRows[i].second.hasPayload) {
                html += "<td style='padding:8px'>" + String(enhancedResultsRows[i].second.payloadLength) + "B</td>";
            } else {
                html += "<td style='padding:8px'>-</td>";
            }
        }
        
        html += "</tr>";
    }
    
    html += F(
        "</table></div>"
        "<div style='margin-top:10px'>"
        "<a class='btn' href='/baseline_results.csv'>Download CSV</a> "
        "<a class='btn' href='/baseline_results'>Open Full Page</a>"
    );
    
    if (currentBaselineConfig.capturePayload) {
        html += " <a class='btn' href='/baseline_results_detailed.txt'>Detailed Report</a>";
    } else {
        // Show detailed report whenever there are Wi-Fi results with metadata
        bool hasWiFiResults = false;
        for (size_t i = 0; i < enhancedResultsRows.size(); ++i) {
            if (enhancedResultsRows[i].second.hasWiFiMeta) { hasWiFiResults = true; break; }
        }
        if (hasWiFiResults) {
            html += " <a class='btn' href='/baseline_results_detailed.txt'>Detailed Report</a>";
        }
    }
    
    html += F("</div></div>");
    
    xSemaphoreGive(resultsMutex);
    return html;
}

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
                "<style>body{margin:0;padding:24px;background:#0f0f23;color:#e6ffee;font-family:Segoe UI}</style></head><body>"
                "<div style='max-width:720px;margin:0 auto;background:#1a1f2b;padding:22px;border-radius:14px'>"
                "<h2 style='color:#9be7a6'>Baseline already running</h2>"
                "<p>When it finishes, you'll hear three beeps.</p>"
                "<p><a href='/' style='color:#78f0a8'>Home</a></p></div></body></html>");
            return;
        }
        
        // Parse enhanced parameters
        String modeStr = "wifi";
        uint32_t secs = 60;
        int16_t rssiThreshold = -100;
        bool capturePayload = false;
        
        if (req->hasParam("mode", true)) {
            modeStr = req->getParam("mode", true)->value();
        }
        if (req->hasParam("secs", true)) {
            secs = req->getParam("secs", true)->value().toInt();
        }
        if (req->hasParam("rssi_threshold", true)) {
            rssiThreshold = req->getParam("rssi_threshold", true)->value().toInt();
        }
        if (req->hasParam("capture_payload", true)) {
            capturePayload = true;
        }
        
        BaselineMode mode = BaselineMode::WIFI_ONLY;
        if (modeStr == "ble") mode = BaselineMode::BLE_ONLY;
        if (modeStr == "both") mode = BaselineMode::WIFI_AND_BLE;
        
        startEnhancedBaseline(mode, secs, rssiThreshold, capturePayload);
        
        String msg = "Baseline started with RSSI >= " + String(rssiThreshold) + " dBm";
        if (capturePayload) {
            msg += " (Payload capture enabled - max " + String(Config::MAX_PAYLOAD_DEVICES) + " devices)";
        }
        
        req->send(200, "text/html",
            "<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>"
            "<style>body{margin:0;padding:24px;background:#0f0f23;color:#e6ffee;font-family:Segoe UI}"
            ".card{max-width:720px;margin:0 auto;background:#1a1f2b;border-radius:14px;padding:22px}</style>"
            "</head><body><div class='card'>"
            "<h2 style='color:#9be7a6'>Baseline Started</h2>"
            "<p>" + msg + "</p>"
            "<p>When baseline completes, you'll hear three beeps and results will appear on the home page.</p>"
            "<p><a href='/' style='color:#78f0a8'>Home</a></p>"
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
    
    server.on("/baseline_results_detailed.txt", HTTP_GET, [](AsyncWebServerRequest *req) {
        String payload;
        
        if (xSemaphoreTake(resultsMutex, pdMS_TO_TICKS(500)) == pdTRUE) {
            payload = detailedReportTxt.length() ? detailedReportTxt : 
                      String("No detailed report available.\n");
            xSemaphoreGive(resultsMutex);
        } else {
            payload = "Results temporarily unavailable.\n";
        }
        
        AsyncWebServerResponse *res = req->beginResponse(200, "text/plain", payload);
        res->addHeader("Content-Disposition", "attachment; filename=\"baseline_detailed.txt\"");
        req->send(res);
    });
    
    server.on("/memory_status", HTTP_GET, [](AsyncWebServerRequest *req) {
        String json = "{";
        json += "\"free_heap\":" + String(ESP.getFreeHeap()) + ",";
        json += "\"payload_memory\":" + String(currentPayloadMemory) + ",";
        json += "\"max_payload_memory\":" + String(Config::MAX_PAYLOAD_MEMORY) + ",";
        json += "\"max_devices\":" + String(Config::MAX_PAYLOAD_DEVICES);
        json += "}";
        req->send(200, "application/json", json);
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
    Serial.println("\n[BOOT] OUI-Spy Enhanced (RSSI filtering + Payload capture)");
    
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
    Serial.printf("[MEMORY] Free heap: %u bytes\n", ESP.getFreeHeap());
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