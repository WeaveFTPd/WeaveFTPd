#!/usr/bin/env python3
"""Isolated master/slave FTP regression test; see docs/Live-Downloads.md."""
import ftplib,hashlib,io,json,os,pathlib,secrets,socket,ssl,struct,subprocess,sys,threading,time,zlib

if len(sys.argv)!=2:
    raise SystemExit("Usage: sudo unshare -n sh -c 'ip link set lo up; python3 tests/live_downloads.py STAGE' (STAGE contains weaveftpd.candidate)")
if os.readlink('/proc/self/ns/net')==os.readlink('/proc/1/ns/net'):
    raise SystemExit('Refusing to open test FTP ports in the host network namespace; use unshare -n')
stage=pathlib.Path(sys.argv[1]).resolve(); base=stage/('integration-'+str(int(time.time())))
base.mkdir(mode=0o700,exist_ok=True)
for d in ['etc/users','etc/groups','etc/certs','site/LIVE','userdata','logs']:(base/d).mkdir(parents=True,exist_ok=True)
def openssl(*args):subprocess.run(['openssl',*args],cwd=base,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
if not (base/'etc/certs/server.crt').exists():
    openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','2','-keyout','etc/certs/ca.key','-out','etc/certs/ca.crt','-subj','/CN=Isolated Test CA')
    for name,cn,ext in [('server','localhost','subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n'),('slave','LOCAL','extendedKeyUsage=clientAuth\n')]:
        openssl('req','-newkey','rsa:2048','-nodes','-keyout',f'etc/certs/{name}.key','-out',f'etc/certs/{name}.csr','-subj',f'/CN={cn}')
        (base/f'etc/certs/{name}.ext').write_text(ext)
        openssl('x509','-req','-in',f'etc/certs/{name}.csr','-CA','etc/certs/ca.crt','-CAkey','etc/certs/ca.key','-CAcreateserial','-days','2','-out',f'etc/certs/{name}.crt','-extfile',f'etc/certs/{name}.ext')
password=secrets.token_urlsafe(22)
salt=secrets.token_bytes(4);pw_hash='$'+salt.hex()+'$'+hashlib.pbkdf2_hmac('sha1',password.encode(),salt,100,20).hex()
(base/'etc/passwd').write_text(f'tester:{pw_hash}:1000:1000::/:/bin/false\n')
(base/'etc/group').write_text('Test:1000:tester\n')
(base/'etc/users/tester').write_text('USER Added by test\nGENERAL 0,120 -1 0 0\nFLAGS 13\nDIR /\nHOMEDIR /\nCREDITS 5000000\nRATIO 3\nLOGINSLOTS 30\nMAXSIM 0\nUPLOADSLOTS 10\nDOWNLOADSLOTS 3\nPRIMARY_GROUP Test\nGROUP Test 0\nIP *@127.0.0.1\n')
(base/'etc/permissions.yml').write_text('[]\n')
(base/'etc/slave_masks.txt').write_text('LOCAL 127.0.0.1\n')
common=dict(timezone='UTC',tls_enabled=True,tls_cert=str(base/'etc/certs/server.crt'),tls_key=str(base/'etc/certs/server.key'),debug=True,log_console=True,free_space_mb=0)
master=dict(common,mode='master',listen_port=22321,storage_path=str(base/'site'),rootpath='/',datapath=str(base/'userdata'),acl_base_path='/',passwd_file=str(base/'etc/passwd'),public_ip='127.0.0.1',pasv_min=42321,pasv_max=42340,passthrough=True,dl_incomplete=True,max_users=30,max_users_per_ip=30,max_connections=30,sections=['LIVE'],master=dict(listen_host='127.0.0.1',control_port=22399,slave_ca_cert=str(base/'etc/certs/ca.crt'),slave_masks_file=str(base/'etc/slave_masks.txt'),remerge_mode='off'),zipscript=dict(enabled=True,sections=dict(sfv=['/LIVE/*']),sfv=dict(force_first=False,delete_bad_crc=True,allow_resume=True,restrict_files=False),media=dict(enabled=False),race=dict(cwd_race_stats=False,stor_race_stats=False)))
slave=dict(common,mode='slave',slave=dict(name='LOCAL',master_host='127.0.0.1',master_port=22399,roots=[str(base/'site')],bind_ip='127.0.0.1',pasv_port_min=42400,pasv_port_max=42430,master_ca_cert=str(base/'etc/certs/ca.crt'),client_cert=str(base/'etc/certs/slave.crt'),client_key=str(base/'etc/certs/slave.key')))
context=ssl.create_default_context(cafile=str(base/'etc/certs/ca.crt'))
class FTP(ftplib.FTP_TLS):
    def ntransfercmd(self,cmd,rest=None):
        self.voidcmd('PRET '+cmd)
        return super().ntransfercmd(cmd,rest)
def connect(protected=True,active=False):
    f=FTP(context=context,timeout=12);f.connect('127.0.0.1',22321);f.login('tester',password)
    if protected:f.prot_p()
    f.set_pasv(not active);f.voidcmd('TYPE I');return f
processes=[];reports=[]
def launch(passthrough):
    master['passthrough']=passthrough
    for name,cfg in [('master',master),('slave',slave)]:
        (base/f'{name}.json').write_text(json.dumps(cfg))
        log=open(base/f'{name}-{passthrough}.log','wb')
        p=subprocess.Popen([str(stage/'weaveftpd.candidate'),'-config',str(base/f'{name}.json')],cwd=base,stdout=log,stderr=subprocess.STDOUT)
        processes.append((p,log))
        if name=='master':time.sleep(.4)
    end=time.monotonic()+25
    while True:
        try:
            f=connect();f.mkd('/LIVE/ready-'+str(passthrough));f.quit();break
        except Exception:
            if time.monotonic()>end:raise
            time.sleep(.3)
def stop():
    for p,log in reversed(processes):
        p.terminate()
        try:p.wait(timeout=10)
        except subprocess.TimeoutExpired:p.kill();p.wait()
        log.close()
    processes.clear()
def policy(f,value):
    master['dl_incomplete']=value;(base/'master.json').write_text(json.dumps(master));f.sendcmd('SITE REHASH')
def recv_exact(c,n):
    b=bytearray()
    while len(b)<n:
        chunk=c.recv(n-len(b))
        if not chunk:raise AssertionError(f'premature data EOF {len(b)}/{n}')
        b.extend(chunk)
    return bytes(b)
def read_rest(f,c,initial,result):
    try:
        out=bytearray(initial)
        while True:
            b=c.recv(65536)
            if not b:break
            out.extend(b)
        c.close();reply=f.voidresp();result.update(data=bytes(out),reply=reply)
    except Exception as e:result.update(data=bytes(out),error=str(e))
def downloaded_bytes():
    lines=(base/'etc/users/tester').read_text().splitlines()
    return next((int(s.split()[2]) for s in lines if s.startswith('ALLDN ')),0)
def stream_case(passthrough,protected,active,kind):
    bytes_before=downloaded_bytes()
    tag=f'{passthrough}-{protected}-{active}-{kind}'
    directory='/LIVE/Race.'+tag;u=connect(protected,active);u.mkd(directory)
    path=directory+'/payload.bin';payload=secrets.token_bytes(1024*1024+713)
    if kind=='crc':u.storbinary('STOR '+directory+'/release.sfv',io.BytesIO(b'payload.bin 00000001\n'))
    else:u.storbinary('STOR '+directory+'/release.sfv',io.BytesIO(('payload.bin %08X\n'%(zlib.crc32(payload)&0xffffffff)).encode()))
    c=u.transfercmd('STOR '+path);prefix=131072;c.sendall(payload[:prefix])
    deadline=time.monotonic()+5
    while (not (base/'site'/path.lstrip('/')).exists() or (base/'site'/path.lstrip('/')).stat().st_size<prefix):
        if time.monotonic()>deadline:raise AssertionError('upload not visible on disk')
        time.sleep(.01)
    admin=connect()
    for cmd in ['DELE '+path]:
        try:admin.sendcmd(cmd)
        except ftplib.error_perm as e:assert str(e).startswith('550'),str(e)
        else:raise AssertionError('live source was deletable')
    if kind=='disabled':
        policy(admin,False);d=connect(protected,active)
        try:d.transfercmd('RETR '+path)
        except ftplib.error_perm as e:assert str(e).startswith('550'),str(e)
        else:raise AssertionError('disabled policy permitted live RETR')
        d.close();c.sendall(payload[prefix:]);c.unwrap().close() if protected else c.close();u.voidresp();policy(admin,True)
        reports.append(dict(case=tag,disabled_rejected=True));u.quit();admin.quit();return
    readers=[]
    for offset in [0,4096]:
        d=connect(protected,active);data=d.transfercmd('RETR '+path,rest=offset if offset else None)
        initial=recv_exact(data,prefix-offset)
        assert initial==payload[offset:prefix],'initial prefix mismatch'
        result={};thread=threading.Thread(target=read_rest,args=(d,data,initial,result));thread.start()
        readers.append((d,thread,result,offset))
    # Both followers have received bytes while STOR is still open.
    assert all(t.is_alive() for _,t,_,_ in readers),'download completed before upload'
    if kind=='abort':
        # Force an actual TCP reset (not a clean TLS EOF).
        c.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0));c.close()
        try:u.voidresp()
        except ftplib.Error:pass
    else:
        for i in range(prefix,len(payload),65536):c.sendall(payload[i:i+65536]);time.sleep(.004)
        c.unwrap().close() if protected else c.close()
        try:u.voidresp()
        except ftplib.Error:
            if kind!='crc':raise
    for d,t,r,offset in readers:
        t.join(15);assert not t.is_alive(),'follower hung'
        if kind in ('abort','crc'):assert 'error' in r and not r.get('reply','').startswith('226'),r
        else:assert r.get('reply','').startswith('226') and r['data']==payload[offset:],{k:v for k,v in r.items() if k!='data'}
        d.close()
    expected_download_bytes=2*len(payload)-4096 if kind=='ok' else 0
    end=time.monotonic()+2
    while downloaded_bytes()-bytes_before!=expected_download_bytes and time.monotonic()<end:time.sleep(.01)
    assert downloaded_bytes()-bytes_before==expected_download_bytes,'live download statistics used the initial size hint or counted a failed download'
    if kind=='ok':
        # Completed download/resume still works and has the full expected hash.
        out=io.BytesIO();admin.retrbinary('RETR '+path,out.write,rest=8192)
        assert out.getvalue()==payload[8192:]
    reports.append(dict(case=tag,live_readers=2,bytes=len(payload),sha256=hashlib.sha256(payload).hexdigest(),source_failure_rejected=kind in ('abort','crc'),tls=protected,active=active))
    u.close();admin.close()
def resume_upload_case(passthrough,abort=False):
    u=connect();directory='/LIVE/Resume.'+str(passthrough)+'.'+str(abort);u.mkd(directory)
    path=directory+'/resumed.bin';payload=secrets.token_bytes(786433);offset=65536
    u.storbinary('STOR '+path,io.BytesIO(payload[:offset]))
    c=u.transfercmd('STOR '+path,rest=offset);c.sendall(payload[offset:131072])
    end=time.monotonic()+5
    while (base/'site'/path.lstrip('/')).stat().st_size<131072:
        if time.monotonic()>end:raise AssertionError('resumed upload not progressing')
        time.sleep(.01)
    d=connect();data=d.transfercmd('RETR '+path);initial=recv_exact(data,131072)
    assert initial==payload[:131072]
    r={};t=threading.Thread(target=read_rest,args=(d,data,initial,r));t.start()
    if abort:
        c.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0));c.close()
        try:u.voidresp()
        except ftplib.Error:pass
    else:
        c.sendall(payload[131072:]);c.unwrap().close();u.voidresp()
    t.join(15);assert not t.is_alive(),'resumed source follower hung'
    if abort:
        assert 'error' in r,'failed resumed source incorrectly succeeded'
        preserved=(base/'site'/path.lstrip('/')).read_bytes()
        assert preserved[:offset]==payload[:offset],'failed resume damaged the existing prefix'
        if passthrough:assert len(preserved)==offset,'slave failed to truncate a reset resume back to its original offset'
        # In proxy mode the master sees the reset, while its separate slave
        # socket closes cleanly. Existing behavior keeps the appended prefix;
        # the master must still fail the follower rather than reply 226.
        else:assert offset<=len(preserved)<=131072
    else:assert r.get('reply','').startswith('226') and r.get('data')==payload,'resumed source truncated'
    d.close();u.close();reports.append(dict(case='resumed-upload-'+str(passthrough)+'-'+str(abort),abort=abort,ok=True))
def delayed_source_eof_case(passthrough):
    u=connect();directory='/LIVE/Delayed.Source.EOF.'+str(passthrough);u.mkd(directory)
    path=directory+'/release.sfv';payload=b'file.r00 12345678\n'*63
    c=u.transfercmd('STOR '+path);c.sendall(payload)
    end=time.monotonic()+5
    while not (base/'site'/path.lstrip('/')).exists() or (base/'site'/path.lstrip('/')).stat().st_size!=len(payload):
        if time.monotonic()>end:raise AssertionError('metadata not on disk')
        time.sleep(.01)
    readers=[]
    for _ in range(3):
        d=connect();d.sock.settimeout(45);data=d.transfercmd('RETR '+path);data.settimeout(45)
        initial=recv_exact(data,len(payload));assert initial==payload
        result={};t=threading.Thread(target=read_rest,args=(d,data,initial,result));t.start()
        readers.append((d,t,result))
    fourth=connect()
    try:fourth.transfercmd('RETR '+path)
    except ftplib.error_perm as e:assert 'Maximum simultaneous downloads reached (3)' in str(e),str(e)
    else:raise AssertionError('fourth reader bypassed the existing three-slot policy')
    fourth.close()
    # This reproduces the production case: all bytes have arrived, but the
    # upstream server does not close its data connection until after 20s.
    time.sleep(21.5)
    try:
        assert all(t.is_alive() for _,t,_ in readers),'follower incorrectly timed out before source EOF'
    finally:
        c.unwrap().close()
    u.voidresp()
    for d,t,result in readers:
        t.join(10);assert not t.is_alive(),'follower not released after source EOF'
        assert result.get('reply','').startswith('226') and result.get('data')==payload,result.get('error','wrong data')
        d.close()
    retry=connect();received=io.BytesIO();retry.retrbinary('RETR '+path,received.write)
    assert received.getvalue()==payload,'slots remained occupied after completion'
    retry.quit()
    # Reacquire all three slots together, rather than only proving one is free.
    next_path=directory+'/next.nfo';source=u.transfercmd('STOR '+next_path);source.sendall(b'next')
    slots=[]
    for _ in range(3):
        d=connect();data=d.transfercmd('RETR '+next_path);initial=recv_exact(data,4)
        result={};t=threading.Thread(target=read_rest,args=(d,data,initial,result));t.start()
        slots.append((d,t,result))
    source.unwrap().close();u.voidresp()
    for d,t,result in slots:
        t.join(10);assert not t.is_alive() and result.get('reply','').startswith('226') and result.get('data')==b'next',result
        d.close()
    u.quit()
    reports.append(dict(case='delayed-source-eof-'+str(passthrough),live_readers=3,waited_beyond_old_20s_limit=True,three_slot_limit_preserved=True,slots_released=True))

try:
    for passthrough in [True,False]:
        launch(passthrough)
        for protected,active,kind in [(True,False,'ok'),(True,True,'ok'),(False,False,'ok'),(False,True,'ok'),(True,False,'abort'),(False,True,'abort'),(True,False,'crc'),(True,False,'disabled')]:
            stream_case(passthrough,protected,active,kind)
            print(json.dumps(reports[-1]),flush=True)
        for abort in [False,True]:
            resume_upload_case(passthrough,abort)
            print(json.dumps(reports[-1]),flush=True)
        delayed_source_eof_case(passthrough)
        print(json.dumps(reports[-1]),flush=True)
        stop()
    (stage/'integration-result.json').write_text(json.dumps(dict(ok=True,cases=reports,network='isolated namespace',control_mtls=True,binary_sha256=hashlib.sha256((stage/'weaveftpd.candidate').read_bytes()).hexdigest()),indent=2))
    print('INTEGRATION PASS',flush=True)
finally:stop()
