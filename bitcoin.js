var net = require('net');
var crypto = require('crypto');
var opensocket = true;
function parsePacket(p) {
	var magic = p.readUInt32LE(0);
	if (magic != 0xd9b4bef9) return -1;
	var obj = {};
	var x;
	for (x=4; x<16; x++) if (p[x] == 0) break;
	obj.command = p.toString('ascii',4,x);
	var payloadsize = p.readUInt32LE(16);
	obj.payload = p.slice(24,24+payloadsize);

	var round1 = crypto.createHash('sha256');
	round1.update(obj.payload);
	var hash1 = round1.digest();
	
	var round2 = crypto.createHash('sha256');
	round2.update(hash1);
	var hash2 = round2.digest();
	var hashsent = p.readUInt32LE(20);
	var hashtrim = hash2.readUInt32LE(0);
	if (hashsent != hashtrim) return -2;

	switch (obj.command) {
	case 'verack':
		console.log('verack with size',obj.payload.length);
		break;
	case 'version':
		parseVersion(obj);
		break;
	case 'inv':
		//parseInv(obj);
		break;
	case 'addr':
		parseAddr(obj);
		break;
	default:
		console.log(obj);
	}
}
function makepacket(command,payload) {
	var packet = new Buffer(24 + payload.length);
	packet.fill(0xff);
	packet[0] = 0xf9;
	packet[1] = 0xbe;
	packet[2] = 0xb4;
	packet[3] = 0xd9;
	packet.fill(0,4,16);
	packet.write(command,4,12,'ascii');
	packet.writeUInt32LE(payload.length,16); // payload size
	//console.log('payload size',payload.length);
	
	var round1 = crypto.createHash('sha256');
	round1.update(payload);
	var hash1 = round1.digest();
	
	var round2 = crypto.createHash('sha256');
	round2.update(hash1);
	var hash2 = round2.digest();
	//process.stdout.write(hash2);
	//console.log(hash2);
	
	//packet.writeUInt32LE(0xaabbccdd,20); // payload checksum
	hash2.copy(packet,20,0,4);
	payload.copy(packet,24);
	return packet;
}
function makeVersion() {
	var agent = "Node-js toy";
	if (agent.length > 0xfd) process.exit(-1);
	var p = new Buffer(86+agent.length);
	p.writeUInt32LE(70001,0);				// 0
	
	p.writeUInt32LE(1,4); // services			// 4
	p.writeUInt32LE(0,8); // services			// 8
	
	var now = Date.now();
	p.writeUInt32LE(Math.floor(now/1000),12);// 12
	p.writeUInt32LE(0,16);					// 16
	var dest = net_addr(0,1,'127.0.0.1',8333);
	dest.copy(p,20,4);					// 20
	
	var src = net_addr(0,1,'10.0.0.14',0);
	src.copy(p,46,4);						// 46->72
	p.writeUInt32LE(0,72);					// 72->76 noonce
	p.writeUInt32LE(0,76);					// 76->80
	
	p.writeInt8(agent.length,80);				// 80->81
	p.write(agent,81,agent.length,'ascii');
	p.writeUInt32LE(0,81+agent.length);
	p.writeInt8(1,85+agent.length);
	
	var last = makepacket('version',p);
	return last;
}
function parseVersion(packet) {
	var p = packet.payload;
	var o = {};
	o.version = p.readUInt32LE(0);
	o.servicesl = p.readUInt32LE(4);
	o.servicesh = p.readUInt32LE(8);
	o.tsl = p.readUInt32LE(12);
	o.tsh = p.readUInt32LE(16);
	var agentsize = p.readInt8(80);
	o.agent = p.toString('ascii',81,81+agentsize);
	o.startheight = p.readUInt32LE(81+agentsize);
	console.log(o);
}
function parseInv(packet) {
	var p = packet.payload;
	var o = {};
	var count = p.readInt8(0);
	var offset = 1;
	if (count > 64) {
		console.log('too many things in inv packet',count);
		return -3;
	}
	for (var x=0; x<count; x++) {
		var item = p.slice(offset+(36*x),offset+(36*(x+1)));
		var parsed = {};
		parsed.type = item.readUInt32LE(0);
		parsed.id = item.slice(4,36);
		console.log('inv item '+(x+1)+'/'+count+' type:'+parsed.type,parsed.id);
	}
}
function parseAddr(packet) {
	var p = packet.payload;
	var o = {};
	var count = p.readInt8(0);
	var offset = 1;
	if (count > 64) {
		console.log('too many things in addr packet',count);
		return -3;
	}
	for (var x=0; x<count; x++) {
		var item = p.slice(offset+(30*x),offset+(30*(x+1)));
		var out = parseNetAddr(item);
		console.log('addr item '+(x+1)+'/'+count,item,out);
	}
}
function parseNetAddr(p) {
	var o = {};
	o.ts = new Date(p.readUInt32LE(0)*1000);
	o.servicesl = p.readUInt32LE(4);
	o.servicesh = p.readUInt32LE(8);
	var ip = [];
	for (var x=0; x<4; x++) {
		ip.push(''+p[24+x]);
	}
	o.ip = ip.join('.');
	o.port = p.readUInt16BE(28);
	return o;
}
function net_addr(time,services,ip,port) {
	var p = new Buffer(30);
	p.fill(0xaa,0,30);
	p.writeUInt32LE(time,0);
	p.writeUInt32LE(services,4); // services
	p.writeUInt32LE(0,8); // services
	p.fill(0,12,22);
	p.fill(0xff,22,24);
	var parts = ip.split('.');
	for (var x=0; x<4; x++) {
		p[24+x] = parseInt(parts[x]);
	}
	p.writeUInt16LE(port,28);
	return p;
}
var p = makeVersion();
//console.log('packet size',p.length);
//process.stdout.write(p);
if (opensocket) {
	var loopback = new Connection('127.0.0.1',8333);
	loopback.socket.write(p);
	//setTimeout(process.exit,20000);
}
function Connection(ip,port) {
	var socket = net.createConnection(8333,ip);
	this.socket = socket;
	socket.on('data',function (input) {
		parsePacket(input);
	});
}
