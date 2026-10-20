#!/usr/bin/env python3
"""Real FTP TLS-role matrix in an isolated network namespace; see Live-Downloads.md."""
import ftplib,hashlib,json,os,pathlib,runpy,secrets,socket,ssl,sys,threading,time

if len(sys.argv) not in (2,3):raise SystemExit('Usage: unshare -n ... python3 tests/fxp_tls_roles.py STAGE [--regression]')
stage=pathlib.Path(sys.argv[1]).resolve();regression=len(sys.argv)==3 and sys.argv[2]=='--regression'
if os.readlink('/proc/self/ns/net')==os.readlink('/proc/1/ns/net'):raise SystemExit('Use an isolated network namespace')
reports=[];runroot=stage/('fxp-roles-'+str(time.time_ns()));runroot.mkdir(mode=0o700)
fixture_path=pathlib.Path(__file__).with_name('live_downloads.py')
for mode in (['direct'] if regression else ['direct','proxy']):
    case_stage=runroot/mode;case_stage.mkdir(mode=0o700);(case_stage/'weaveftpd.candidate').symlink_to(stage/'weaveftpd.candidate')
    sys.argv=[str(fixture_path),str(case_stage)]
    fx=runpy.run_path(str(fixture_path),run_name='fxp_tls_fixture');base=fx['base'];cfg=fx['master']
    def new_session():return fx['connect']()
    def peer_context(client,version):
        if client:c=ssl.create_default_context(cafile=str(base/'etc/certs/ca.crt'))
        else:
            c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);c.load_cert_chain(str(base/'etc/certs/server.crt'),str(base/'etc/certs/server.key'))
        c.minimum_version=c.maximum_version=version;return c
    def transfer(f,command,path,direction,payload,peer_client,version,rest=None,protected=True):
        listener=None;raw=None;data=None
        try:
            f.sendcmd('PRET '+('STOR ' if direction=='upload' else 'RETR ')+path)
            if command=='PORT':
                listener=socket.create_server(('127.0.0.1',0));listener.settimeout(4)
                port=listener.getsockname()[1];f.sendcmd('PORT 127,0,0,1,'+str(port//256)+','+str(port%256))
            else:
                host,port=ftplib.parse227(f.sendcmd(command));raw=socket.create_connection((host,port),timeout=4)
            if rest is not None:f.sendcmd('REST '+str(rest))
            f.putcmd(('STOR ' if direction=='upload' else 'RETR ')+path);pre=f.getresp();assert pre.startswith(('125','150')),pre
            if listener is not None:raw,_=listener.accept()
            raw.settimeout(4)
            if protected:
                c=peer_context(peer_client,version);data=c.wrap_socket(raw,server_hostname='localhost') if peer_client else c.wrap_socket(raw,server_side=True)
                negotiated=data.version();assert negotiated==('TLSv1.2' if version==ssl.TLSVersion.TLSv1_2 else 'TLSv1.3'),negotiated
            else:data=raw;negotiated='clear'
            if direction=='upload':
                data.sendall(payload)
                if protected:data.unwrap().close()
                else:data.close()
                actual=(base/'site'/path.lstrip('/')).read_bytes()
            else:
                chunks=[]
                while True:
                    b=data.recv(65536)
                    if not b:break
                    chunks.append(b)
                data.close();actual=b''.join(chunks)
            final=f.voidresp();assert final.startswith('226'),final
            expected=payload[rest or 0:] if direction=='download' else payload
            assert actual==expected,f'file bytes differ: actual={len(actual)} expected={len(expected)} actual_sha256={hashlib.sha256(actual).hexdigest()} expected_sha256={hashlib.sha256(expected).hexdigest()}'
            return dict(tls=negotiated,bytes=len(actual),sha256=hashlib.sha256(actual).hexdigest(),reply=final)
        finally:
            if data is not None:data.close()
            if raw is not None:raw.close()
            if listener is not None:listener.close()
    def live_sscn_download(version):
        u=new_session();path=directory+'/live-'+version.name+'.bin';source=u.transfercmd('STOR '+path);source.sendall(payload[:65536])
        f=None;data=None
        try:
            end=time.monotonic()+4
            disk=base/'site'/path.lstrip('/')
            while not disk.exists() or disk.stat().st_size<65536:
                if time.monotonic()>end:raise AssertionError('live source did not progress')
                time.sleep(.01)
            f=new_session();f.sendcmd('SSCN ON');f.sendcmd('PRET RETR '+path);host,port=ftplib.parse227(f.sendcmd('PASV'));raw=socket.create_connection((host,port),timeout=4)
            f.putcmd('RETR '+path);assert f.getresp().startswith('150')
            data=peer_context(False,version).wrap_socket(raw,server_side=True);initial=fx['recv_exact'](data,65536);assert initial==payload[:65536]
            result={};reader=threading.Thread(target=fx['read_rest'],args=(f,data,initial,result));reader.start()
            source.sendall(payload[65536:]);source.unwrap().close();assert u.voidresp().startswith('226')
            reader.join(10);assert not reader.is_alive(),'live SSCN reader remained active'
            assert result.get('reply','').startswith('226') and result.get('data')==payload,result.get('error','truncated live data')
            assert 'CLIENT' in f.sendcmd('SSCN')
            return dict(bytes=len(payload),sha256=hashlib.sha256(payload).hexdigest(),reply=result['reply'])
        finally:
            source.close();u.close()
            if data is not None:data.close()
            if f is not None:f.close()
    try:
        fx['launch'](mode=='direct');seed=new_session();directory='/LIVE/FXP.TLS.Roles';seed.mkd(directory)
        payload=secrets.token_bytes(131109);seed_path=directory+'/seed.bin';seed.storbinary('STOR '+seed_path,__import__('io').BytesIO(payload));seed.quit()
        versions=[ssl.TLSVersion.TLSv1_3] if regression else [ssl.TLSVersion.TLSv1_2,ssl.TLSVersion.TLSv1_3]
        for version in versions:
            settings=[('PASV',False),('PASV',True),('CPSV',False)] if regression else [('PASV',False),('PASV',True),('PORT',False),('PORT',True),('CPSV',False),('CPSV',True)]
            for command,on in settings:
                for direction in ['upload','download']:
                    f=new_session();case=f'{mode}-{version.name}-{command}-SSCN-{on}-{direction}'
                    try:
                        reply=f.sendcmd('SSCN '+('ON' if on else 'OFF'));assert ('CLIENT' if on else 'SERVER') in reply,reply
                        target=directory+'/'+case+'.bin' if direction=='upload' else seed_path
                        result=transfer(f,command,target,direction,payload,not(on or command=='CPSV'),version)
                        assert ('CLIENT' if on else 'SERVER') in f.sendcmd('SSCN'),'SSCN state changed after file transfer'
                        reports.append(dict(case=case,ok=True,**result))
                    except Exception as e:reports.append(dict(case=case,ok=False,error=type(e).__name__+': '+str(e)))
                    finally:f.close()
            if not regression:
                try:reports.append(dict(case=f'{mode}-{version.name}-live-PASV-SSCN-ON',ok=True,**live_sscn_download(version)))
                except Exception as e:reports.append(dict(case=f'{mode}-{version.name}-live-PASV-SSCN-ON',ok=False,error=type(e).__name__+': '+str(e)))
                # Persistent ON, REST, listings after FXP, and explicit OFF on one session.
                f=new_session()
                try:
                    f.sendcmd('SSCN ON')
                    for n in range(2):
                        result=transfer(f,'PASV',seed_path,'download',payload,False,version,rest=123+n)
                        assert 'CLIENT' in f.sendcmd('SSCN')
                        reports.append(dict(case=f'{mode}-{version.name}-persistent-SSCN-REST-{n}',ok=True,**result))
                    lines=[];f.retrlines('LIST '+directory,lines.append);assert any('seed.bin' in l for l in lines)
                    assert 'CLIENT' in f.sendcmd('SSCN');reports.append(dict(case=f'{mode}-{version.name}-LIST-after-SSCN-ON',ok=True))
                    f.sendcmd('SSCN OFF');transfer(f,'CPSV',seed_path,'download',payload,False,version)
                    result=transfer(f,'PASV',seed_path,'download',payload,True,version)
                    reports.append(dict(case=f'{mode}-{version.name}-CPSV-then-PASV-SSCN-OFF',ok=True,**result))
                    f.sendcmd('SSCN ON');f.sendcmd('PROT C')
                    result=transfer(f,'PASV',seed_path,'download',payload,True,version,protected=False)
                    reports.append(dict(case=f'{mode}-{version.name}-PROT-C-after-SSCN-ON',ok=True,**result))
                except Exception as e:reports.append(dict(case=f'{mode}-{version.name}-state-regressions',ok=False,error=type(e).__name__+': '+str(e)))
                finally:f.close()
    finally:fx['stop']()
out=dict(ok=all(x['ok'] for x in reports),cases=reports,binary_sha256=hashlib.sha256((stage/'weaveftpd.candidate').read_bytes()).hexdigest(),network='isolated namespace')
(stage/('tls-regression-before.json' if regression else 'tls-role-result.json')).write_text(json.dumps(out,indent=2))
print(json.dumps(dict(ok=out['ok'],cases=len(reports),failures=[x for x in reports if not x['ok']],binary_sha256=out['binary_sha256'])),flush=True)
raise SystemExit(0 if out['ok'] else 1)
