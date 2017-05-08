var net = require('net');
var crypto = require('crypto');
var MongoClient = require('mongodb').MongoClient;
var ObjectID = require('mongodb').ObjectID

var connid = 0;
var peers;

function Connection(ip,port,keep) {
	this.nick = ip+'#'+connid++;
	var socket = net.createConnection(port,ip);
	this.socket = socket;
	socket.on('data',function (input) {
		try {
			if (input.length < 20) {
				peers.update({_id:this._id},{$set:{unreachable:true,invalid:true}},this.log);
				this.log('invalid packet');
				this.socket.destroy();
				return;
			}
			this.parsePacket(input);
		} catch (err) {
			this.log(input);
			throw err;
		}
	}.bind(this));
	socket.on('error',function () {
		this.log('connection lost due to error');
		peers.remove({_id:this._id},function () {
			//peers.findOne(function (err,row) {
				//console.log(row);
				//var out = new Connection(row._id.split(':')[0],row._id.split(':')[1],true);
			//}.bind(this));
		}.bind(this));
		//peers.update({_id:this._id},{$set:{unreachable:true}},this.log);
	}.bind(this));
	var p = makeVersion(ip,port,'47.54.167.25',0);
	socket.write(p);
	if (!keep) setTimeout(function() {
		socket.destroy();
	},120000);
	this.log('connecting...');
	this._id = ip+':'+port;
}
Connection.prototype.log = function log() {
	var out = Array.prototype.slice.call(arguments);
	out.unshift(this.nick+":");
	console.log.apply(this,out);
}
Connection.prototype.parsePacket = function parsePacket(p) {
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
	var hash1 = round1.digest('base64');
	
	var round2 = crypto.createHash('sha256');
	round2.update(hash1);
	var hash2 = round2.digest();
	var hashsent = p.readUInt32LE(20);
	var hashtrim = hash2.readUInt32LE(0);
	if (hashsent != hashtrim) {
		// TODOthis.log('hash mismatch',hashsent,hashtrim);
		//return -2;
	}

	switch (obj.command) {
	case 'verack':
		this.log('verack with size',obj.payload.length);
		break;
	case 'version':
		this.parseVersion(obj);
		break;
	case 'inv':
		this.parseInv(obj);
		break;
	case 'addr':
		this.parseAddr(obj);
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
function makeVersion(destip,destport,sourceip,sourceport) {
	var agent = "Node-js toy";
	if (agent.length > 0xfd) process.exit(-1);
	var p = new Buffer(91+agent.length);
	p.fill(0xaa,0,91+agent.length);
	console.log(p);
	p.writeUInt32LE(70002,0);				// 0
	console.log(p);
	
	p.writeUInt32LE(1,4); // services			// 4
	p.writeUInt32LE(0,8); // services			// 8
	
	var now = Date.now();
	p.writeUInt32LE(Math.floor(now/1000),12);// 12
	p.writeUInt32LE(0,16);					// 16
	var dest = net_addr(0,1,destip,destport);
	dest.copy(p,20,4);					// 20
	
	var src = net_addr(0,1,sourceip,sourceport);
	src.copy(p,46,4);						// 46->72
	p.writeUInt32LE(0,72);					// 72->76 noonce
	p.writeUInt32LE(0,76);					// 76->80
	
	p.writeInt8(agent.length,80);				// 80->81
	p.write(agent,81,agent.length,'ascii');
	p.writeUInt32LE(0,81+agent.length);
	p.writeInt8(1,85+agent.length);
	p.writeUInt32LE(0,86+agent.length);
	p.writeInt8(1,90+agent.length);
	
	var last = makepacket('version',p);
	return last;
}
Connection.prototype.parseVersion = function parseVersion(packet) {
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
	this.log('parseVersion',o);
	
	peers.update({_id:this._id},{$set:{
		lastSeen:new Date(),
		unreachable:false
	},},function (err,res) {
		this.log('set lastseen',err,res);
	}.bind(this));
}
Connection.prototype.parseInv = function parseInv(packet) {
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
		if (parsed.type != 1) console.log('inv item '+(x+1)+'/'+count+' type:'+parsed.type,parsed.id);
	}
}
Connection.prototype.parseAddr = function parseAddr(packet) {
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
		console.log('got peer packet',out);
		peers.insert({_id:out.ip + ':'+out.port,advertisedTS:out.ts},function (err,result) {
			if (err) {
				peers.update({_id:out.ip + ':'+out.port},{$set:{advertisedTS:out.ts}},function (err,res) {
					if (err) {
						this.log(err,result);
						this.log('addr item '+(x+1)+'/'+count,item,out);
						return;
					}
					//new Connection(out.ip,out.port,false);
				}.bind(this));
				return;
			}
			new Connection(out.ip,out.port,false);
		}.bind(this));
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
MongoClient.connect('mongodb://localhost:27017/bitcoin',function (err,db) {
	peers = db.collection('peers');
	peers.find().limit(100).toArray(function (err,rows) {
		//console.log(err,rows);
		for (var i=0; i<rows.length; i++) {
			//var out = new Connection(rows[i]._id.split(':')[0],rows[i]._id.split(':')[1],true);
		}
	});
	var loopback = new Connection('127.0.0.1',8333,true);
});
