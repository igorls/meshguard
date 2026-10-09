"""Loopback interoperability with an independently built native FFI library."""
import base64,ctypes as c,json,socket,struct,sys,time
request=json.load(sys.stdin)
lib=c.CDLL(sys.argv[1])
def bind(name,args,result=None):
 f=getattr(lib,name);f.argtypes=args;f.restype=result;return f
init=bind('meshguard_init',[c.c_void_p,c.c_uint16],c.c_void_p)
join=bind('meshguard_join',[c.c_void_p,c.c_void_p,c.c_uint16],c.c_int)
send=bind('meshguard_send',[c.c_void_p,c.c_void_p,c.c_void_p,c.c_uint32],c.c_int)
recv=bind('meshguard_recv',[c.c_void_p]*4,c.c_int)
public=bind('meshguard_get_pubkey_b64',[c.c_void_p,c.c_void_p])
destroy=bind('meshguard_destroy',[c.c_void_p])
browser=bytes.fromhex(request['public']);wg=bytes.fromhex(request['wgPublic'])
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(('127.0.0.1',0));sock.settimeout(.1)
port=sock.getsockname()[1]
endpoint=b'\x01\x04'+bytes([127,0,0,1])+bytes(12)+struct.pack('<H',port)
gossip=browser+b'\x01'+struct.pack('<Q',1)+endpoint+b'\x01'+wg+bytes(20)+b'\x03'
assert len(gossip)==115
ctx=init(bytes([2])*32,0)
if not ctx: raise RuntimeError('Native identity initialization failed')
native_endpoint=None
def pump():
 global native_endpoint
 try: packet,address=sock.recvfrom(4096)
 except socket.timeout: return None
 if packet[0]==1 and len(packet)>=50 and packet[1:33]!=bytes(32):
  native_endpoint=address
  sock.sendto(b'\x03'+browser+packet[33:41]+bytes(8)+b'\x01'+gossip,address)
 return packet
try:
 b=c.create_string_buffer(48);public(ctx,b)
 if base64.b64decode(b.value).hex()!=request['nativePublic']:raise RuntimeError('Native identity differs from WASM')
 if join(ctx,bytes([127,0,0,1]),port)!=0:raise RuntimeError('Native join failed')
 end=time.monotonic()+10
 while native_endpoint is None and time.monotonic()<end:pump()
 if native_endpoint is None:raise RuntimeError('Native did not contact loopback browser adapter')
 frames=[]
 for sample in request['samples']:
  data=bytes.fromhex(sample['packet']);expected=bytes.fromhex(sample['plaintext'])
  sock.sendto(data,native_endpoint)
  end=time.monotonic()+5;received=False
  while time.monotonic()<end:
   pump();out=c.create_string_buffer(1024);length=c.c_uint32();sender=c.create_string_buffer(32)
   if recv(ctx,out,c.byref(length),sender)==0:
    if sender.raw!=browser or out.raw[:length.value]!=expected:raise RuntimeError('Native decoded unexpected data')
    received=True;break
  if not received:raise RuntimeError('WASM-to-native delivery failed')
  payload=c.create_string_buffer(expected)
  rc=send(ctx,browser,payload,len(expected))
  if rc!=0:raise RuntimeError('Native send failed: '+str(rc))
  end=time.monotonic()+5;reply=None
  while time.monotonic()<end:
   packet=pump()
   if packet and packet[0]==0x50:reply=packet;break
  if reply is None:raise RuntimeError('No native encrypted reply')
  frames.append(reply.hex())
 print(json.dumps({'nativeReceived':len(frames),'nativePackets':frames}))
finally:destroy(ctx);sock.close()
