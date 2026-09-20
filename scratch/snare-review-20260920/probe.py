import contextlib, hashlib, hmac, json, os, pathlib, signal, socket, subprocess, sys, tempfile, threading, time
BIN='/tmp/snare-review-build/debug/snare'
SECRET=b'synthetic-review-secret'
BODY=json.dumps({'repository': {'owner': {'login': 'review'}, 'name': 'canary'}}).encode()
def payload(event='ping'):
    sig=hmac.new(SECRET,BODY,hashlib.sha256).hexdigest()
    return (f'POST / HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {len(BODY)}\r\nX-GitHub-Event: {event}\r\nX-Hub-Signature-256: sha256={sig}\r\n\r\n').encode()+BODY
class Server:
    def __init__(self, td, extra='', unix=False):
        self.td=pathlib.Path(td); self.unix=unix; self.sockpath=self.td/'snare.sock'; self.portfile=self.td/'port'
        addr='unix:'+str(self.sockpath) if unix else '127.0.0.1:0'
        self.config=self.td/'config'
        self.config.write_text(f'listen = "{addr}"; user = "root"; maxjobs = 1; github {{ match ".*" {{ secret = "{SECRET.decode()}"; {extra} }} }}')
        self.procs=[]; self.start()
    def start(self):
        self.portfile.unlink(missing_ok=True)
        env={'PATH':'/usr/bin:/bin','SHELL':'/bin/sh','SNARE_DEBUG_PORT_PATH':str(self.portfile),'TMPDIR':str(self.td)}
        self.proc=subprocess.Popen([BIN,'-d','-c',str(self.config)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,start_new_session=True)
        self.procs.append(self.proc)
        for _ in range(200):
            if self.proc.poll() is not None: return False
            if self.portfile.exists(): return True
            time.sleep(.01)
        self.close(); raise RuntimeError('startup timed out')
    def conn(self, timeout=2):
        if self.unix:
            s=socket.socket(socket.AF_UNIX); s.settimeout(timeout); s.connect(str(self.sockpath)); return s
        return socket.create_connection(('127.0.0.1',int(self.portfile.read_text())),timeout)
    def request(self,event='ping',timeout=2):
        with self.conn(timeout) as s:
            s.sendall(payload(event)); return s.recv(1024).split(b'\r\n')[0].decode()
    def close(self):
        for p in self.procs:
            with contextlib.suppress(ProcessLookupError): os.killpg(p.pid, signal.SIGKILL)
            p.wait(); p.stderr.close()
def rss(p):
    return int(next(x.split()[1] for x in pathlib.Path(f'/proc/{p.pid}/status').read_text().splitlines() if x.startswith('VmRSS:')))
def ticks(p):
    vals=pathlib.Path(f'/proc/{p.pid}/stat').read_text().split(); return int(vals[13])+int(vals[14])
def run(kind,mode):
    with tempfile.TemporaryDirectory(prefix='snare-review-') as td:
        extra=''
        if kind=='timeout':
            delay='30' if mode=='vuln' else '0.1'
            extra=f'cmd = "if [ %e = issues ]; then echo started > {td}/started; sleep {delay}; :; else echo ran > {td}/next; fi"; timeout = 1;'
        sn=Server(td, extra, kind=='unix')
        try:
            assert sn.request()=='HTTP/1.1 200 OK'
            if kind=='headers':
                before=rss(sn.proc)
                with sn.conn() as s:
                    s.sendall(b'POST / HTTP/1.1\r\nX-Padding: ')
                    n=24*1024*1024 if mode=='vuln' else 32
                    s.sendall(b'a'*n)
                    time.sleep(.2)
                    growth=rss(sn.proc)-before
                    # Complete without an HMAC: all memory was consumed before auth.
                    s.sendall(b'\r\nContent-Length: 0\r\n\r\n')
                    response=s.recv(1024).split(b'\r\n')[0].decode()
                assert growth>20000 if mode=='vuln' else growth<4096
                print(f'header_memory_growth_over_20MiB={growth>20000}; final_response={response}')
                print(f'measured_growth_kib={growth}',file=sys.stderr)
            elif kind=='slow':
                conns=[]; stop=threading.Event()
                try:
                    if mode=='vuln':
                        for _ in range(17):
                            s=sn.conn(); s.sendall(b'POST / HTTP/1.1\r\nX-Slow: '); conns.append(s)
                    def drip():
                        while not stop.wait(1):
                            for s in conns:
                                with contextlib.suppress(OSError): s.sendall(b'a')
                    thread=threading.Thread(target=drip); thread.start()
                    time.sleep(11)
                    try: result=sn.request(timeout=1)
                    except socket.timeout: result='timed out'
                    assert result==('timed out' if mode=='vuln' else 'HTTP/1.1 200 OK')
                    print('valid_request_after_11_seconds='+result)
                finally:
                    stop.set(); thread.join()
                    for s in conns: s.close()
            elif kind=='timeout':
                assert sn.request('issues')=='HTTP/1.1 200 OK'
                for _ in range(200):
                    if pathlib.Path(td,'started').exists(): break
                    time.sleep(.01)
                assert pathlib.Path(td,'started').exists()
                assert sn.request('push')=='HTTP/1.1 200 OK'
                time.sleep(2)
                before=ticks(sn.proc); time.sleep(1); cpu=(ticks(sn.proc)-before)/os.sysconf('SC_CLK_TCK')
                completed=pathlib.Path(td,'next').exists()
                assert completed==(mode=='control')
                print(f'next_job_completed_after_3_timeouts={completed}; cpu_busy={cpu>.5}')
                print(f'cpu_seconds_over_one_second={cpu}',file=sys.stderr)
            elif kind=='unix':
                sn.proc.terminate(); sn.proc.wait()
                stale=sn.sockpath.exists()
                if mode=='control': sn.sockpath.unlink()
                started=sn.start()
                if started: assert sn.request()=='HTTP/1.1 200 OK'
                else:
                    err=sn.proc.stderr.read().decode(); assert 'Address already in use' in err,err
                assert started==(mode=='control')
                print(f'socket_remained_after_stop={stale}; restart_succeeded={started}')
        finally: sn.close()
if __name__=='__main__': run(*sys.argv[1:])
