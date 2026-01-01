#include <Arduino.h>
#include <WiFi.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <Preferences.h>
#include <NimBLEDevice.h>
#include <vector>
#include <map>
#include <algorithm>

// ================================
// Wi-Fi AP + Web
// ================================
static const char* AP_SSID = "snoopuntothem";
static const char* AP_PASS = nullptr; // open AP

AsyncWebServer server(80);
Preferences prefs;

// ================================
// Pin and Buzzer Definitions - Xiao ESP32 S3
// ================================
#define BUZZER_PIN     3     // GPIO3 (D2) for buzzer
#define BUZZER_FREQ    2000  // Hz
#define BUZZER_DUTY    127   // ~50%
#define BEEP_DURATION  200   // ms
#define BEEP_PAUSE     150   // ms
#define LED_PIN        21    // onboard LED (inverted)

static const int BUZZER_CH = 3;

static inline void ledOn()  { pinMode(LED_PIN, OUTPUT); digitalWrite(LED_PIN, LOW); }
static inline void ledOff() { pinMode(LED_PIN, OUTPUT); digitalWrite(LED_PIN, HIGH); }

static void buzzerOn(int freq = BUZZER_FREQ, uint8_t duty = BUZZER_DUTY){
  pinMode(BUZZER_PIN, OUTPUT);
  ledcAttachPin(BUZZER_PIN, BUZZER_CH);
  ledcSetup(BUZZER_CH, freq, 8);
  ledcWrite(BUZZER_CH, duty);
}
static void buzzerOff(){ ledcWrite(BUZZER_CH, 0); }

static void beepOnce(int durMs = BEEP_DURATION, int freq = BUZZER_FREQ, uint8_t duty = BUZZER_DUTY){
  buzzerOn(freq, duty); ledOn(); delay(durMs); buzzerOff(); ledOff();
}
static void beepPattern(uint8_t count = 2){
  for(uint8_t i=0;i<count;i++){ beepOnce(); if(i+1<count) delay(BEEP_PAUSE); }
}
static void startupBeep(){ beepPattern(2); }
static void baselineDoneBeep(){ beepPattern(3); }
static void detectBeep(){ beepPattern(1); }

// ================================
// Filters + Results
// ================================
static std::vector<String> filters; // OUI (XX:XX:XX) or full MAC (XX:XX:XX:XX:XX:XX)

struct Observed {
  String name;    // BLE Complete Local Name or Wi-Fi SSID
  String source;  // "BLE" or "Wi-Fi"
  int16_t rssi = -127;   // dBm baseline strength
  bool hasRssi = false;
};

enum class BaselineMode { WIFI_ONLY, BLE_ONLY, WIFI_AND_BLE };
using DetectionMode = BaselineMode;

static volatile bool baselineRunning = false;
static volatile bool detectionRunning = false;

// Last results
static std::vector<std::pair<String, Observed> > lastResultsRows;  // key=MAC12 (no colons)
static String lastResultsHTMLFull;
static String lastResultsCSV;

// ================================
// Utils
// ================================
static String toUpperNoDelim(const String &s){
  String out; out.reserve(s.length());
  for (size_t i=0;i<s.length();++i){
    char c = s[i];
    if (c==':' || c=='-' || c==' ' || c=='\r' || c=='\n' || c=='\t') continue;
    out += (char)toupper(c);
  }
  return out;
}
static String macPretty(const String& macNoDelim12){
  if(macNoDelim12.length() < 12) return macNoDelim12;
  String p;
  for(int i=0;i<12;i+=2){ if(i) p += ':'; p += macNoDelim12.substring(i, i+2); }
  return p;
}

static inline void setBestRssi(Observed &o, int rssiDbm){
  // RSSI is negative dBm; closer to 0 is stronger (e.g., -40 > -80)
  if (!o.hasRssi || rssiDbm > o.rssi){
    o.rssi = (int16_t)rssiDbm;
    o.hasRssi = true;
  }
}



// ================================
// RSSI Color Coding
// ================================
static const int RSSI_GREEN  = -55;
static const int RSSI_YELLOW = -67;
static const int RSSI_ORANGE = -75;

static const char* rssiClass(bool has, int rssi){
  if (!has) return "rssi-unk";
  if (rssi >= RSSI_GREEN)  return "rssi-g";
  if (rssi >= RSSI_YELLOW) return "rssi-y";
  if (rssi >= RSSI_ORANGE) return "rssi-o";
  return "rssi-r";
}

static String rssiCellHtml(const Observed& o){
  if (!o.hasRssi) return String("<span class='rssi rssi-unk'>-</span>");
  return "<span class='rssi " + String(rssiClass(true, o.rssi)) + "'>" + String(o.rssi) + " dBm</span>";
}


static void loadFilters(){
  filters.clear();
  prefs.begin("ouispy", true);
  uint16_t n = prefs.getUShort("count", 0);
  for(uint16_t i=0;i<n;i++){
    String key = "f" + String(i);
    String val = prefs.getString(key.c_str(), "");
    if(val.length()) filters.push_back(val);
  }
  prefs.end();
}
static void saveFilters(){
  prefs.begin("ouispy", false);
  prefs.putUShort("count", filters.size());
  for(size_t i=0;i<filters.size();i++){
    String key = "f" + String(i);
    prefs.putString(key.c_str(), filters[i]);
  }
  prefs.end();
}
static void clearFilters(){
  // Remove stored entries and reset in RAM
  prefs.begin("ouispy", false);
  uint16_t n = prefs.getUShort("count", 0);
  for(uint16_t i=0;i<n;i++){
    String key = "f" + String(i);
    prefs.remove(key.c_str());
  }
  prefs.putUShort("count", 0);
  prefs.end();
  filters.clear();
}
static bool addFilterIfNew(const String& entry){
  // entry may be OUI or full MAC, keep as user typed (colons)
  for(size_t i=0;i<filters.size();++i){
    if (filters[i].equalsIgnoreCase(entry)) return false;
  }
  filters.push_back(entry);
  saveFilters();
  return true;
}

// ================================
// Detection (continuous, *drops AP*, manual restart to exit)
// ================================
class DetectBLECallbacks: public NimBLEAdvertisedDeviceCallbacks {
  void onResult(NimBLEAdvertisedDevice* dev) override {
    if(!detectionRunning || filters.empty()) return;
    String macNo = toUpperNoDelim(String(dev->getAddress().toString().c_str())); // 12 hex
    for(size_t i=0;i<filters.size();++i){
      String f = filters[i]; f.toUpperCase();
      String fNo = toUpperNoDelim(f);
      if (fNo.length()==6) { // OUI
        if (macNo.startsWith(fNo)) {
          Serial.printf("[DETECT BLE] OUI match %s RSSI:%d\n", macNo.c_str(), dev->getRSSI());
          detectBeep();
          return;
        }
      } else if (fNo.length()==12) {
        if (macNo == fNo) {
          Serial.printf("[DETECT BLE] MAC match %s RSSI:%d\n", macNo.c_str(), dev->getRSSI());
          detectBeep();
          return;
        }
      }
    }
  }
};
static DetectBLECallbacks detectBleCb;

struct DetectParams { DetectionMode mode; };

static void detectionTask(void* pv){
  DetectParams p = *(DetectParams*)pv; delete (DetectParams*)pv;
  detectionRunning = true;
  Serial.printf("[DETECT] starting, mode=%d (0=WiFi,1=BLE,2=Both)\n", (int)p.mode);

  // Drop AP as requested
  WiFi.softAPdisconnect(true);
  delay(100);
  WiFi.mode(WIFI_OFF);
  delay(100);

  // BLE setup if needed
  NimBLEScan* bleScan = nullptr;
  if (p.mode == DetectionMode::BLE_ONLY || p.mode == DetectionMode::WIFI_AND_BLE){
    NimBLEDevice::init("detect");
    bleScan = NimBLEDevice::getScan();
    bleScan->setAdvertisedDeviceCallbacks(&detectBleCb, false);
    bleScan->setActiveScan(true);
    bleScan->setInterval(45);
    bleScan->setWindow(15);
    bleScan->start(0, nullptr, false); // continuous
    Serial.println("[DETECT] BLE scan active");
  }

  // Wi-Fi loop if needed
  if (p.mode == DetectionMode::WIFI_ONLY || p.mode == DetectionMode::WIFI_AND_BLE){
    WiFi.mode(WIFI_STA);
    WiFi.disconnect(true, true);
    delay(200);
    Serial.println("[DETECT] Wi-Fi scan loop active");
  }

  // Continuous loop until reset/power-cycle
  for(;;){
    if (p.mode == DetectionMode::WIFI_ONLY || p.mode == DetectionMode::WIFI_AND_BLE){
      int n = WiFi.scanNetworks(false, true); // async=false, show_hidden=true
      for (int i=0;i<n;i++){
        String bssidNo = toUpperNoDelim(WiFi.BSSIDstr(i)); // 12 hex
        for(size_t k=0;k<filters.size();++k){
          String f = filters[k]; f.toUpperCase();
          String fNo = toUpperNoDelim(f);
          if (fNo.length()==6){
            if (bssidNo.startsWith(fNo)){
              Serial.printf("[DETECT Wi-Fi] OUI match %s SSID:%s RSSI:%d\n",
                            bssidNo.c_str(), WiFi.SSID(i).c_str(), WiFi.RSSI(i));
              detectBeep();
              break;
            }
          } else if (fNo.length()==12){
            if (bssidNo == fNo){
              Serial.printf("[DETECT Wi-Fi] MAC match %s SSID:%s RSSI:%d\n",
                            bssidNo.c_str(), WiFi.SSID(i).c_str(), WiFi.RSSI(i));
              detectBeep();
              break;
            }
          }
        }
      }
      WiFi.scanDelete();
    }
    delay(150);
  }
}

// ================================
// Baseline collectors
// ================================
class BaselineBLECollector : public NimBLEAdvertisedDeviceCallbacks {
public:
  std::map<String, Observed> entries; // key = 12 hex chars
  void onResult(NimBLEAdvertisedDevice* dev) override {
    String macNo = toUpperNoDelim(String(dev->getAddress().toString().c_str()));
    if (macNo.length()!=12) return;
    Observed &o = entries[macNo];
    o.source = "BLE";
    setBestRssi(o, dev->getRSSI());
    if (dev->haveName()) {
      String nm = String(dev->getName().c_str());
      if (nm.length()) o.name = nm;
    }
  }
};

// ================================
// HTML (Index) — Dark + Green
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
               box-shadow:0 10px 28px rgba(0,0,0,.45);padding:22px}
    h1{margin:0 0 8px 0;font-size:30px;font-weight:700;color:#9be7a6}
    .muted{color:#a8cbb5}
    .section{margin:16px 0;padding:16px;border:1px solid #22314a;border-radius:10px;background:#0f1420}
    textarea,input[type=number]{width:100%;max-width:720px;padding:10px;border-radius:8px;border:1px solid #2a405f;
                                background:#09101b;color:#dff6e6;font-family:Consolas,Menlo,monospace}
    label{display:block;margin:6px 0}
    .btn{display:inline-block;border:1px solid #2fe26c;background:#1db954;color:#00100a;
         padding:10px 16px;border-radius:8px;cursor:pointer;text-decoration:none;font-weight:600}
    .btn:hover{filter:brightness(1.05)}
    a{color:#78f0a8}
    th,td{border-bottom:1px solid #26354d}
    .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}

    /* RSSI pill color coding */
    .rssi{display:inline-block;min-width:76px;text-align:center;padding:4px 8px;border-radius:999px;font-weight:700}
    .rssi-unk{background:#2a3344;color:#cbd5e1}
    .rssi-g{background:#1db954;color:#00100a}
    .rssi-y{background:#f4d03f;color:#1b1400}
    .rssi-o{background:#ff9f1a;color:#1f1200}
    .rssi-r{background:#ff4d4d;color:#1a0000}
  </style>
  <script>
    function addLineOnce(textareaId, value){
      const ta = document.getElementById(textareaId);
      const lines = ta.value.split(/\\r?\\n/).map(s=>s.trim()).filter(s=>s.length>0);
      if(!lines.includes(value)) lines.push(value);
      ta.value = lines.join('\n'); // real newline (fixed)
    }
    function addOUI(oui){ addLineOnce('filtersTa', oui); }
    function addMAC(mac){ addLineOnce('filtersTa', mac); }
  </script>
</head>
<body>
  <div class="container">
    <h1>OUI-SPY</h1>
    <p class="muted">Enter OUIs or full MACs; run a baseline scan; click MAC parts to add filters; start live detection (Wi-Fi, BLE, or both) which drops the AP until reboot.</p>

    <div class="section">
      <h3 style="margin-top:0;color:#9be7a6">Detection Filters</h3>
      <form method="POST" action="/save" style="margin-bottom:10px">
  <textarea id="filtersTa" name="filters" rows="7" placeholder="AA:BB:CC or AA:BB:CC:11:22:33, one per line">%FILTERS%</textarea><br><br>
  <input class="btn" type="submit" value="Save Filters">
  <button class="btn" formaction="/filters_clear" formmethod="POST" type="submit"
          style="margin-left:8px"
          onclick="return confirm('Clear all detection filters?');">
    Clear Filters
  </button>
</form>
<p class="muted">OUI = first 3 bytes. Full MAC = 6 bytes. One entry per line.</p>
    </div>

    <div class="section">
      <h3 style="margin-top:0;color:#9be7a6">Detection</h3>
      <form method="POST" action="/detect_start">
        <label><input type="radio" name="d_mode" value="wifi" checked> Wi-Fi</label>
        <label><input type="radio" name="d_mode" value="ble"> BLE</label>
        <label><input type="radio" name="d_mode" value="both"> Wi-Fi &amp; BLE</label><br><br>
        <button class="btn" type="submit">Start Detection (drops AP)</button>
        <span class="muted" style="margin-left:8px">Status: %DETECT_STATUS%</span>
      </form>
      <p class="muted">To stop detection, power-cycle or reset the device.</p>
    </div>

    <div class="section">
      <h3 style="margin-top:0;color:#9be7a6">Baseline Scan</h3>
      <form method="POST" action="/baseline_start">
        <label><input type="radio" name="mode" value="wifi" checked> Wi-Fi</label>
        <label><input type="radio" name="mode" value="ble"> BLE</label>
        <label><input type="radio" name="mode" value="both"> Wi-Fi &amp; BLE</label><br><br>
        <label>Duration (seconds): <input type="number" min="5" max="600" value="60" name="secs" style="width:120px"></label><br><br>
        <div class="row">
          <input class="btn" type="submit" value="Start Baseline">
          <a class="btn" href="/baseline_results.csv">Download Results</a>
        </div>
      </form>
      <p class="muted">You’ll hear 3 beeps when baseline finishes; results appear below.</p>
    </div>

    %LAST_RESULTS_SECTION%
  </div>
</body>
</html>
)HTML";

static String renderIndexResultsSection(); // fwd

static String buildIndex(){
  // filters block
  String fl;
  for(size_t i=0;i<filters.size();++i){ if(i) fl += "\n"; fl += filters[i]; }
  String resultsSection = renderIndexResultsSection();
  String status = detectionRunning ? "Running (AP down)" : "Stopped";

  String html = String(INDEX_HTML);
  html.replace("%FILTERS%", fl);
  html.replace("%LAST_RESULTS_SECTION%", resultsSection);
  html.replace("%DETECT_STATUS%", status);
  return html;
}

// ================================
// Baseline (background task)
// ================================
struct BaselineParams { BaselineMode mode; uint32_t secs; };

static void buildResultsArtifacts(const std::map<String, Observed>& macMap); // fwd

static void baselineTask(void* pv){
  BaselineParams p = *(BaselineParams*)pv; delete (BaselineParams*)pv;
  baselineRunning = true;
  Serial.printf("[BASELINE] start mode=%d secs=%u\n", (int)p.mode, (unsigned)p.secs);

  BaselineBLECollector bleCb;
  NimBLEScan* bleScan = nullptr;

  if (p.mode == BaselineMode::BLE_ONLY || p.mode == BaselineMode::WIFI_AND_BLE){
    NimBLEDevice::init("baseline");
    bleScan = NimBLEDevice::getScan();
    bleScan->setAdvertisedDeviceCallbacks(&bleCb, false);
    bleScan->setActiveScan(true);
    bleScan->setInterval(45);
    bleScan->setWindow(15);
    bleScan->start(0, nullptr, false);
  }

  std::map<String, Observed> macMap;
  uint32_t startMs = millis();
  uint32_t durMs   = p.secs * 1000UL;

  if (p.mode == BaselineMode::WIFI_ONLY || p.mode == BaselineMode::WIFI_AND_BLE){
    WiFi.mode(WIFI_AP_STA);
    WiFi.disconnect(true, true);
    delay(100);
    while (millis() - startMs < durMs){
      int n = WiFi.scanNetworks(false, true);
      for (int i=0;i<n;i++){
        String bssidNo = toUpperNoDelim(WiFi.BSSIDstr(i));
        if (bssidNo.length()!=12) continue;
        Observed &o = macMap[bssidNo];
        o.source = "Wi-Fi";
        setBestRssi(o, WiFi.RSSI(i));
        String ssid = WiFi.SSID(i);
        if (ssid.length() && o.name.length()==0) o.name = ssid;
      }
      WiFi.scanDelete();
      delay(150);
    }
  } else {
    while (millis() - startMs < durMs) delay(100);
  }

  if (bleScan) bleScan->stop();

  // Merge BLE into Wi-Fi map
  for (std::map<String, Observed>::const_iterator it = bleCb.entries.begin();
       it != bleCb.entries.end(); ++it){
    const String &mac = it->first;
    const Observed &oBle = it->second;
    std::map<String, Observed>::iterator it2 = macMap.find(mac);
    if (it2 == macMap.end()){
      macMap[mac] = oBle;
    } else {
      if (it2->second.name.length()==0 && oBle.name.length()) it2->second.name = oBle.name;
      // Keep strongest RSSI across sources
      if (oBle.hasRssi) setBestRssi(it2->second, oBle.rssi);
    }
  }

  buildResultsArtifacts(macMap);
  Serial.printf("[BASELINE] done, entries=%u\n", (unsigned)macMap.size());
  baselineDoneBeep();
  baselineRunning = false;
  vTaskDelete(nullptr);
}
static void startBaseline(BaselineMode mode, uint32_t secs){
  if (baselineRunning) { Serial.println("[BASELINE] already running"); return; }
  if (secs < 5) secs = 5; if (secs > 600) secs = 600;
  BaselineParams* bp = new BaselineParams{mode, secs};
  xTaskCreatePinnedToCore(baselineTask, "baselineTask", 8192, bp, 1, NULL, 0);
}

// ================================
// WEB
// ================================
static void setupWeb(){
  server.on("/", HTTP_GET, [](AsyncWebServerRequest *req){
    req->send(200, "text/html", buildIndex());
  });

  // Save filters
  server.on("/save", HTTP_POST, [](AsyncWebServerRequest *req){
    if(req->hasParam("filters", true)){
      String body = req->getParam("filters", true)->value();
      filters.clear();
      int start=0;
      while(start < body.length()){
        int nl = body.indexOf('\n', start);
        String line = (nl==-1)? body.substring(start) : body.substring(start, nl);
        start = (nl==-1)? body.length() : nl+1;
        line.trim();
        if(!line.length()) continue;
        // keep user's colon formatting; validate length
        String no = toUpperNoDelim(line);
        if (no.length()==6 || no.length()==12) filters.push_back(line);
      }
      saveFilters();
    }
    req->redirect("/");
  });
// Clear all filters
server.on("/filters_clear", HTTP_POST, [](AsyncWebServerRequest *req){
  clearFilters();
  req->redirect("/");
});
  // Append a single filter via query (used by clickable links)
  server.on("/append_filter", HTTP_GET, [](AsyncWebServerRequest *req){
    if (req->hasParam("v")){
      String v = req->getParam("v")->value();
      v.trim();
      String no = toUpperNoDelim(v);
      if (no.length()==6 || no.length()==12){
        addFilterIfNew(v);
      }
    }
    req->redirect("/");
  });

  // Start baseline
  server.on("/baseline_start", HTTP_POST, [](AsyncWebServerRequest *req){
    if (baselineRunning){
      req->send(200, "text/html",
        "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<style>body{margin:0;padding:24px;background:#0f0f23;color:#e6ffee;font-family:Segoe UI,Tahoma,Arial,sans-serif}"
        ".card{max-width:720px;margin:0 auto;background:#1a1f2b;border:1px solid #22314a;border-radius:14px;padding:22px}</style></head><body>"
        "<div class='card'><h2 style='margin:0 0 10px 0;color:#9be7a6'>Baseline already running</h2>"
        "<p>When it finishes, you’ll hear three beeps and results will appear on the home page.</p>"
        "<p><a href='/' style='color:#78f0a8'>Home</a></p></div></body></html>");
      return;
    }

    String modeStr = "wifi";
    uint32_t secs  = 60;
    if (req->hasParam("mode", true)) modeStr = req->getParam("mode", true)->value();
    if (req->hasParam("secs", true)) secs = req->getParam("secs", true)->value().toInt();

    BaselineMode mode = BaselineMode::WIFI_ONLY;
    if (modeStr == "ble")  mode = BaselineMode::BLE_ONLY;
    if (modeStr == "both") mode = BaselineMode::WIFI_AND_BLE;

    startBaseline(mode, secs);

    req->send(200, "text/html",
      "<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>"
      "<style>body{margin:0;padding:24px;background:#0f0f23;color:#e6ffee;font-family:Segoe UI,Tahoma,Arial,sans-serif}"
      ".card{max-width:720px;margin:0 auto;background:#1a1f2b;border:1px solid #22314a;border-radius:14px;padding:22px}</style>"
      "</head><body><div class='card'>"
      "<h2 style='margin:0 0 10px 0;color:#9be7a6'>Baseline started</h2>"
      "<p>When baseline completes, you’ll hear three beeps and the results will appear on the home page.</p>"
      "<p><a href='/' style='color:#78f0a8'>Home</a> &nbsp; <a href='/baseline_results' style='color:#78f0a8'>Open Full Results</a></p>"
      "</div></body></html>");
  });

  // Results (page & CSV)
  server.on("/baseline_results", HTTP_GET, [](AsyncWebServerRequest *req){
    if (lastResultsHTMLFull.length()){
      req->send(200, "text/html", lastResultsHTMLFull);
    } else {
      req->send(200, "text/html",
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Baseline Results</title></head>"
        "<body style='background:#0f0f23;color:#e6ffee;font-family:Segoe UI,Tahoma,Arial,sans-serif;padding:24px'>"
        "<div style='max-width:720px;margin:0 auto;background:#1a1f2b;border:1px solid #22314a;border-radius:14px;padding:22px'>"
        "<h2 style='margin:0 0 10px 0;color:#9be7a6'>Baseline Results</h2>"
        "<p>No baseline run yet.</p><a href='/' style='color:#78f0a8'>Back</a></div></body></html>");
    }
  });
  server.on("/baseline_results.csv", HTTP_GET, [](AsyncWebServerRequest *req){
    String payload = lastResultsCSV.length() ? lastResultsCSV : String("MAC,Source,RSSI,Complete Local Name\n");
    AsyncWebServerResponse *res = req->beginResponse(200, "text/csv", payload);
    res->addHeader("Content-Disposition", "attachment; filename=\"baseline_results.csv\"");
    req->send(res);
  });

  // Start detection (drops AP; manual restart to stop)
  server.on("/detect_start", HTTP_POST, [](AsyncWebServerRequest *req){
    if (filters.empty()){
      req->send(200, "text/html",
        "<!DOCTYPE html><html><body style='background:#0f0f23;color:#e6ffee;font-family:Segoe UI,Tahoma,Arial,sans-serif;padding:24px'>"
        "<p>Please add at least one filter (OUI or MAC) before starting detection.</p>"
        "<p><a href='/' style='color:#78f0a8'>Back</a></p></body></html>");
      return;
    }
    if (detectionRunning){
      req->send(200, "text/html",
        "<!DOCTYPE html><html><body style='background:#0f0f23;color:#e6ffee;font-family:Segoe UI,Tahoma,Arial,sans-serif;padding:24px'>"
        "<p>Detection already running. AP is dropped. Power-cycle to stop.</p></body></html>");
      return;
    }

    String modeStr = "wifi";
    if (req->hasParam("d_mode", true)) modeStr = req->getParam("d_mode", true)->value();

    DetectionMode mode = DetectionMode::WIFI_ONLY;
    if (modeStr == "ble")  mode = DetectionMode::BLE_ONLY;
    if (modeStr == "both") mode = DetectionMode::WIFI_AND_BLE;

    // Inform user before AP drops
    req->send(200, "text/html",
      "<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>"
      "<style>body{margin:0;padding:24px;background:#0f0f23;color:#e6ffee;font-family:Segoe UI,Tahoma,Arial,sans-serif}"
      ".card{max-width:720px;margin:0 auto;background:#1a1f2b;border:1px solid #22314a;border-radius:14px;padding:22px}</style>"
      "</head><body><div class='card'>"
      "<h2 style='margin:0 0 10px 0;color:#9be7a6'>Starting Detection</h2>"
      "<p>The access point will shut down now. Detection will run continuously ("
      + String(modeStr=="wifi"?"Wi-Fi":modeStr=="ble"?"BLE":"Wi-Fi & BLE")
      + "). Power-cycle to stop.</p>"
      "<p>Close this page.</p>"
      "</div></body></html>");

    // Little delay so response flushes before AP down
    delay(200);

    // Launch background detection task (AP goes down inside the task)
    DetectParams* dp = new DetectParams{mode};
    xTaskCreatePinnedToCore(detectionTask, "detectionTask", 8192, dp, 1, NULL, 0);
  });

  // Health & Beep
  server.on("/health", HTTP_GET, [](AsyncWebServerRequest *req){ req->send(200, "text/plain", "ok"); });
  server.on("/beep",   HTTP_GET, [](AsyncWebServerRequest *req){ detectBeep(); req->send(200, "text/plain", "beep"); });

  server.begin();
  Serial.println("[HTTP] server started");
}

// ================================
// Results builders (single copy)
// ================================
static void buildResultsArtifacts(const std::map<String, Observed>& macMap){
  lastResultsRows.assign(macMap.begin(), macMap.end());
  std::sort(
    lastResultsRows.begin(), lastResultsRows.end(),
    [](const std::pair<String, Observed>& a, const std::pair<String, Observed>& b)->bool{
      if (a.second.source == b.second.source) return a.first < b.first;
      return a.second.source < b.second.source;
    }
  );

  // CSV
  String csv; csv.reserve(2048);
  csv += "MAC,Source,RSSI,Complete Local Name\n";
  for (size_t i=0;i<lastResultsRows.size();++i){
    const String macP = macPretty(lastResultsRows[i].first);
    const String src  = lastResultsRows[i].second.source.length() ? lastResultsRows[i].second.source : String("BLE");
    String nm  = lastResultsRows[i].second.name.length() ? lastResultsRows[i].second.name : String("UNKNOWN");
    nm.replace("\"","\"\"");
    String rssiStr = lastResultsRows[i].second.hasRssi ? String(lastResultsRows[i].second.rssi) : String("");
    csv += "\"" + macP + "\",\"" + src + "\",\"" + rssiStr + "\",\"" + nm + "\"\n";
  }
  lastResultsCSV = csv;

  // Full page HTML
  String html;
  html.reserve(4096);
  html += F(
    "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Baseline Results</title>"
    "<meta name='viewport' content='width=device-width, initial-scale=1'>"
    "<style>"
    "body{margin:0;padding:24px;background:#0f0f23;color:#e6ffee;font-family:'Segoe UI',Tahoma,Arial,sans-serif}"
    ".card{max-width:980px;margin:0 auto;background:#1a1f2b;border:1px solid #22314a;border-radius:14px;"
      "box-shadow:0 10px 28px rgba(0,0,0,.45);padding:22px}"
    "h1{margin:0 0 14px 0;font-size:28px;font-weight:700;color:#9be7a6}"
    "table{width:100%;border-collapse:collapse;margin-top:10px;background:#0f1420;border-radius:10px;overflow:hidden}"
    "th,td{border-bottom:1px solid #26354d;padding:10px 12px;text-align:left}"
    "th{background:#0c111b;color:#9be7a6;font-weight:600}"
    "tr:hover td{background:#11192a}"
    "a.btn{display:inline-block;margin-top:16px;padding:10px 16px;border-radius:8px;text-decoration:none;"
      "background:#1db954;color:#00100a;font-weight:600;border:1px solid #2fe26c}"
    "a.link{color:#78f0a8;text-decoration:none}"
    "a.btn:hover{filter:brightness(1.05)}"
    ".rssi{display:inline-block;min-width:76px;text-align:center;padding:4px 8px;border-radius:999px;font-weight:700}"".rssi-unk{background:#2a3344;color:#cbd5e1}"".rssi-g{background:#1db954;color:#00100a}"".rssi-y{background:#f4d03f;color:#1b1400}"".rssi-o{background:#ff9f1a;color:#1f1200}"".rssi-r{background:#ff4d4d;color:#1a0000}"
    "</style></head><body><div class='card'>"
    "<h1>Baseline Results</h1>"
    "<table><tr><th>MAC</th><th>Source</th><th>RSSI</th><th>Complete Local Name</th></tr>"
  );
  if (lastResultsRows.empty()){
    html += F("<tr><td colspan='4'>No devices observed.</td></tr>");
  } else {
    for (size_t i=0;i<lastResultsRows.size();++i){
      const String macP = macPretty(lastResultsRows[i].first);
      const String oui  = macP.substring(0,8);
      const String dev  = macP.substring(9);
      const String src  = lastResultsRows[i].second.source.length() ? lastResultsRows[i].second.source : String("BLE");
      const String nm   = lastResultsRows[i].second.name.length() ? lastResultsRows[i].second.name : String("UNKNOWN");
      html += "<tr><td>"
              "<a class='link' href='/append_filter?v="+oui+"'>"+oui+"</a>:"
              "<a class='link' href='/append_filter?v="+macP+"'>"+dev+"</a>"
              "</td><td>"+src+"</td><td>"+rssiCellHtml(lastResultsRows[i].second)+"</td><td>"+nm+"</td></tr>";
    }
  }
  html += F("</table>"
            "<div style='margin-top:10px'>"
            "<a class='btn' href='/'>Home</a> "
            "<a class='btn' href='/baseline_results.csv'>Download CSV</a>"
            "</div></div></body></html>");
  lastResultsHTMLFull = html;
}

static String renderIndexResultsSection(){
  if (lastResultsRows.empty()) {
    return String(
      "<div class='section'><h3 style='margin-top:0;color:#9be7a6'>Last Results</h3>"
      "<p class='muted'>No baseline run yet.</p></div>"
    );
  }
  String html;
  html.reserve(2048);
  html += F(
    "<div class='section'><h3 style='margin-top:0;color:#9be7a6'>Last Results</h3>"
    "<p class='muted'>Click the <b>first 3 bytes</b> to add an OUI, or the <b>last 3 bytes</b> to add the full MAC.</p>"
    "<div style='overflow-x:auto'><table style='width:100%;border-collapse:collapse;background:#0f1420'>"
    "<tr><th style='text-align:left;border-bottom:1px solid #26354d;padding:8px;color:#9be7a6'>MAC</th>"
    "<th style='text-align:left;border-bottom:1px solid #26354d;padding:8px;color:#9be7a6'>Source</th>"
    "<th style='text-align:left;border-bottom:1px solid #26354d;padding:8px;color:#9be7a6'>RSSI</th>"
    "<th style='text-align:left;border-bottom:1px solid #26354d;padding:8px;color:#9be7a6'>Complete Local Name</th></tr>"
  );
  for (size_t i=0;i<lastResultsRows.size();++i){
    const String macP = macPretty(lastResultsRows[i].first);
    const String oui  = macP.substring(0,8);
    const String dev  = macP.substring(9);
    const String src  = lastResultsRows[i].second.source.length() ? lastResultsRows[i].second.source : String("BLE");
    const String nm   = lastResultsRows[i].second.name.length() ? lastResultsRows[i].second.name : String("UNKNOWN");
    html += "<tr>"
            "<td style='border-bottom:1px solid #26354d;padding:8px'>"
            "<a href='/append_filter?v="+oui+"' style='color:#78f0a8;text-decoration:none'>"+oui+"</a>"
            ":"
            "<a href='/append_filter?v="+macP+"' style='color:#78f0a8;text-decoration:none'>"+dev+"</a>"
            "</td>"
            "<td style='border-bottom:1px solid #26354d;padding:8px'>" + src + "</td>"
            "<td style='border-bottom:1px solid #26354d;padding:8px'>" + rssiCellHtml(lastResultsRows[i].second) + "</td>"
            "<td style='border-bottom:1px solid #26354d;padding:8px'>" + nm + "</td>"
            "</tr>";
  }
  html += F("</table></div>"
            "<div style='margin-top:10px'>"
            "<a class='btn' href='/baseline_results.csv'>Download Results</a> "
            "<a class='btn' href='/baseline_results'>Open Full Page</a>"
            "</div></div>");
  return html;
}

// ================================
// Setup/Loop
// ================================
void setup(){
  Serial.begin(115200);
  delay(200);
  Serial.println("\n[BOOT] OUI-Spy (detection Wi-Fi/BLE/Both with AP drop, fixed newline add, clickable MAC parts)");

  ledOff();
  startupBeep();

  loadFilters();
  Serial.printf("[BOOT] filters=%u\n", (unsigned)filters.size());

  WiFi.mode(WIFI_AP);
  bool ok = WiFi.softAP(AP_SSID, AP_PASS);
  Serial.printf("[AP] %s, IP=%s\n", ok ? "started" : "FAILED", WiFi.softAPIP().toString().c_str());

  // Web
  setupWeb();

  Serial.println("[READY] open http://192.168.4.1/");
}

void loop(){ delay(250); }
