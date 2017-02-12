# mac-presence
detection of mac hardware identifier 

mac-presence system is basically an attendance taker. Can be used in a home, or office, or mall... etc.  I'm certain this type of Mac address logging and association / location tracking is common for wifi hot spot providers, etc. But most people have no idea...  this system just lets me know who is home or not based on the presence of their mobile devoice.

Intrigued by this wifi data leaking stuff since I watched James Lyne's Ted talk (https://www.ted.com/talks/james_lyne_everyday_cybercrime_and_what_you_can_do_about_it?language=en) (the last demonstration near the end). I emailed him and asked what hardware and software he used. He replied with something like this for the hardware (which is what I have), and for the software it relies on my own python scripts, plus scapy (http://www.secdev.org/projects/scapy/) and airmon-ng (http://www.aircrack-ng.org/).   Of interest is fact that there are far more technically savvy people around these days, but fewer and fewer that actually understand at a low level what is actually happening behind the scenes. I have always needed to understand things from first principals, and feel that I've fallen behind in this regard... so this Homestead system has allowed me to catch up.

Additionally part of my work was motivated by the backlash against "tracking" on the  web through cookies as compared to the non-backlash (due to ignorance I believe) against much more pervasive privacy infringements resulting from app permissions and  wifi data leakage - I wrote a bit about this here.
Scapy and airmon-ng are installed locally on that computer looking for new MAC addresses? Your Python program is also running locally and interfaces with scapy and/or airmon-ng to actually get the MAC addresses?

Hardware
Raspberry Pi Model B Rev 2
Alfa-AWUS051NH USB wifi antennae - specifically this device: http://www.amazon.ca/Alfa-AWUS051NH-802-11a-Wireless-Network/dp/B003YH1X48

Software
a Java GAE application, 
a GAE Cloud Endpoint restful API, 
a Python program and API client which runs a wifi packet sniffer and talks to the API, 
an Android mobile App which pulls from the API, and provides status updates
servos which are controlled by python scripts and the data
Linux OS, Raspberry Pi, hardware interfacing

Python script makes an http call to a restful API interface provided by the back end Google App Engine application - which is really just a one table data store with the following fields: id (mac address) , name (string), device type (string), last seen (datetime), home (boolean)






