This piece of code simulates Ollama server on the port 11434 and tricks most of the bots and even  hackers that are using unsecures publicly available Ollama servers to boost their autonomous agent used for hacking. 
Help protect the internet! Run the fake Ollama and lure these mtfkrs

Launching :

Linux : 
 nohup python3 -u ollama-honeypot.py > nohup.out 2>&1 &

Windows:
python3 ollama-honeypot.py

Logs will be visible in two places : ollama_honeypot.log  and   nohup.out

