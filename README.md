This piece of code simulates Ollama server on the port 11434 and tricks most of the bots and even  hackers that are using not properly secured people's  Ollama servers (exposed to the Internet) to boost their autonomous agent used for hacking. 

Help protecting the internet! Run the fake Ollama and lure these mtfkrs

simplest launching :

Linux : 
```bash
 nohup python3 -u ollama-honeypot.py > nohup.out 2>&1 &
```

Windows:
```bash
python3 ollama-honeypot.py
```
Logs will be visible in two places : ollama_honeypot.log  and   nohup.out

***The more safest approach on Linux Ubuntu :***

1. Add new user with limited rights, add yourself to the same group. Copy the script to the home directory 
   
```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin honeypot
sudo usermod -aG honeypot $USER
sudo mkdir -p /home/ollama-honeypot
sudo cp ollama-honeypot.py /home/ollama-honeypot/ollama-honeypot.py
sudo chown -R honeypot:honeypot /home/ollama-honeypot
sudo chmod 750 /home/ollama-honeypot
```

2. Create a Linux service for Ollama Honeypot

```bash
sudo tee /etc/systemd/system/ollama-honeypot.service > /dev/null << 'EOF'
[Unit]
Description=Ollama Honeypot Service
After=network.target

[Service]
Type=simple
User=honeypot
Group=honeypot
UMask=0027
WorkingDirectory=/home/ollama-honeypot
ExecStart=/usr/bin/python3 -u /home/ollama-honeypot/ollama-honeypot.py
Restart=always
RestartSec=5

StandardOutput=append:/home/ollama-honeypot/nohup.out
StandardError=append:/home/ollama-honeypot/nohup.out

NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/home/ollama-honeypot

[Install]
WantedBy=multi-user.target
EOF

```

3. Launch the service

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ollama-honeypot
sudo systemctl restart ollama-honeypot
systemctl status ollama-honeypot
```

4. check how it works

```bash
sudo chown honeypot:honeypot /home/ollama-honeypot/nohup.out
tail -f /home/ollama-honeypot/nohup.out
tail -f /home/ollama-honeypot/ollama_honeypot.log
```
