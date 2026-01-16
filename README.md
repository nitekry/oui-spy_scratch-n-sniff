# oui-spy_scratch-n-sniff
Modification of colonelpanichacks OUI-SPY Detector  
I am not a Dev, just proof of concept.
Yes, I used AI , But it works.

Added color coded rssi to the baseline target scan.  
Added fox-hunt function  
Segmented functions so prevent continous conflics when editing.  


## Install

```bash
git clone https://github.com/nitekry/oui-spy_scratch-n-sniff
cd oui-spy_scratch-n-sniff

python3 -m venv venv
source venv/bin/activate

pip install esptool platformio
pio run -t upload


