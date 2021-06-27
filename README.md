# FIS_project

#run snort command
sudo snort -A console -i wlp1s0 -u snort -g snort -c /etc/snort/snort.conf 
#edit snort rule
sudo gedit /etc/snort/rules/local.rules
#our snort rule for TCP flood
alert tcp any any -> $HOME_NET 8000 (msg:"TCP Flood"; sid:10000011; detection_filter: track by_src, count 10, seconds 1; rev:001; flow: to_server, established; content: "GET"; nocase; http_method; metadata: service http;)