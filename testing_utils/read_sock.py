#!/usr/bin/env python3
import socket
import os,sys
import re
import time
import select

uds = '/var/run/audispd_events'
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
max_len = 4096
try:
    sock.connect(uds)
    print('Connected socket')
except Exception as e:
    print('Exception socket: {}'.format(e))
    sys.exit(1)
try:
    def data2dic(data):
        stripchars = ' "'
        try:
            return { k.strip(stripchars):v.strip(stripchars) for k,v in (x.split('=',1) for x in data.split()) }
        except:
            return None

    def filterdic(data,regexp=re.compile('a[0-9]+'),typeline='execve'):
        try:
            if data.get('type','').lower() == typeline:
                return { k:data[k] for k in data if re.match(regexp,k) }
            else:
                return None
        except:
            return None

    def dic2list(data):
        try:
            return [ data[k] for k in sorted(data.keys()) ]
        except Exception as e:
            return e

    def print_dict(data):
        try:
            if data:
                for k in data:
                    print('{} = {}'.format(k,data.get(k)))
                print('\n')
        except:
            pass
        finally:
            return data

    def _read_sock(sock):
        timeout_method = True
        sock.setblocking(False)
        try:
            if timeout_method:
                sock.settimeout(10)
                print('Readed 1')
                return sock.recv(max_len)
            else:
                ready = select.select([sock],[],[],10)
                if ready:
                    print('Readed 2')
                    return sock.recv(max_len)
        except Exception as e:
            #print('Exception {}'.format(e))
            pass
        return None

    def readsock(sock):
        global processing
        buffer = _read_sock(sock)
        if buffer:
            buffer = buffer.decode('utf-8')
        while processing:
            if buffer and "\n" in buffer:
                (line, buffer) = buffer.split("\n",1)
                yield line
            else:
                more = _read_sock(sock)
                if more:
                    more = more.decode('utf-8')
                    if buffer:
                        buffer += more
                    else:
                        buffer = more
                else:
                    # if something non blocking is called, end processing
                    #processing = False
                    print('waiting')
                    time.sleep(0.1)
        if buffer:
            yield buffer

    processing = True
    filter_audit_params = re.compile(r'a[0-9]+')
    filter_valid_executables = re.compile(r'^[a-zA-Z][a-zA-Z0-9_.+\-]+$')
    while processing:
        for data in readsock(sock):
            filtered = filterdic(data2dic(data),regexp=filter_audit_params)
            if filtered:
                #print_dict(filtered)
                a=dic2list(filtered)
                print('CAPTURE: {}'.format(' '.join(a)))
        print('END LOOP')

finally:
    print('Closing socket')
    sock.close()
