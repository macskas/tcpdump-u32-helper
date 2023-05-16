new (function() {
	this.UI = new (function(myp) {
		this.parent = myp;

		this.cleanTable = function() {
			const ti = document.getElementById("table-iptables");
			const tr_all = ti.getElementsByTagName('TR');
			let cleanups = [];
			for (let i=0; i<tr_all.length; ++i)
			{
				const td_all = tr_all[i].getElementsByTagName('TD');
				for (let j=0; j<td_all.length; ++j)
				{
					const curtd = td_all[j];
					if (curtd.className === "ti-1") {
						cleanups.push(tr_all[i]);
						break;
					}
				}
			}
			for (let i=0; i<cleanups.length; i++)
			{
				cleanups[i].parentNode.removeChild(cleanups[i]);
			}
		}

		this.addItem = function(type, value, urules) {
			const ti = document.getElementById("table-iptables");
			const item = document.createElement('TR');
			let item_t1 = document.createElement('TD');
			item_t1.innerHTML = type;
			item_t1.className = "ti-1";
			item.appendChild(item_t1);

			let item_t2 = document.createElement('TD');
			item_t2.innerHTML = value;
			item_t2.className = "ti-2";

			item.appendChild(item_t2);
			let item_t3 = document.createElement('TD');
			item_t3.className = "ti-3";

			let chkbox = document.createElement('INPUT');
			chkbox.type = "checkbox"
			chkbox.setAttribute('data-rule', urules);
			item_t3.appendChild(chkbox);
			item.appendChild(item_t3);
			ti.appendChild(item);
		}

		this.stripHEX = function(lines) {
			let hexlist = [];
			for (let i=0; i<lines.length; ++i)  {
				const line = lines[i];
				const m = line.match(/0x[a-f0-9A-F]+:(\s+[a-fA-F0-9\s]+)/);
				if (m == null)
					continue;
				const vals = m[1].match(/([0-9a-fA-F]{2,4})/g);
				if (vals == null)
					continue;
				for (let j=0; j<vals.length; ++j)
				{
					const hlist = vals[j].match(/([0-9A-Fa-f]{2})/g);
					if (hlist == null)
						continue;
					for (let k=0; k<hlist.length; ++k)
					{
						hexlist.push(parseInt(hlist[k], 16));
					}
				}
			}
			return hexlist;
		}

		this.setIPheader = function(opt) {
			document.getElementById('ip-version').innerHTML			= opt.version.toString();
			document.getElementById('ip-ihl').innerHTML				= opt.length.toString();
			document.getElementById('ip-dscp').innerHTML				= "0x"+this.dec2hex(opt.tos);
			document.getElementById('ip-total-length').innerHTML		= opt.total.toString();
			document.getElementById('ip-ecn').innerHTML				= this.dec2bin(opt.ecn, 2);
			document.getElementById('ip-identification').innerHTML	= opt.identification;
			document.getElementById('ip-flags').innerHTML			= this.dec2bin(opt.flags, 3);
			document.getElementById('ip-fragmentoffset').innerHTML	= opt.foff;
			document.getElementById('ip-ttl').innerHTML				= opt.ttl;
			document.getElementById('ip-protocol').innerHTML			= opt.proto;
			document.getElementById('ip-checksum').innerHTML			= opt.checksum;
			document.getElementById('ip-src').innerHTML				= opt.src;
			document.getElementById('ip-dst').innerHTML				= opt.dst;
		};

		this.setTCPheader = function(opt) {
			document.getElementById('tcp-src').innerHTML				= opt.srcport.toString();
			document.getElementById('tcp-dst').innerHTML				= opt.dstport.toString();
			document.getElementById('tcp-seq').innerHTML				= opt.seq.toString();
			document.getElementById('tcp-ackfull').innerHTML			= opt.ack.toString();
			document.getElementById('tcp-doff').innerHTML			= opt.doff.toString();
			document.getElementById('tcp-reserved').innerHTML		= this.dec2bin(opt.reserved, 3);
			document.getElementById('tcp-ns').innerHTML				= opt.ns.toString();
			document.getElementById('tcp-cwr').innerHTML				= opt.cwr.toString();
			document.getElementById('tcp-ece').innerHTML				= opt.ece.toString();
			document.getElementById('tcp-urg').innerHTML				= opt.urg.toString();
			document.getElementById('tcp-ack').innerHTML				= opt.ack.toString();
			document.getElementById('tcp-psh').innerHTML				= opt.psh.toString();
			document.getElementById('tcp-rst').innerHTML				= opt.rst.toString();
			document.getElementById('tcp-syn').innerHTML				= opt.syn.toString();
			document.getElementById('tcp-fin').innerHTML				= opt.fin.toString();
			document.getElementById('tcp-window').innerHTML			= opt.window.toString();
			document.getElementById('tcp-checksum').innerHTML		= opt.checksum.toString();
			document.getElementById('tcp-urgent').innerHTML			= opt.urgent.toString();

		};

		this.setUDPheader = function(opt) {
			document.getElementById('udp-src').innerHTML				= opt.srcport.toString();
			document.getElementById('udp-dst').innerHTML				= opt.dstport.toString();
			document.getElementById('udp-length').innerHTML			= opt.length.toString();
			document.getElementById('udp-checksum').innerHTML		= opt.checksum.toString();
		};

		this.dec2bin = function (n,total) {
			if (total === undefined)
				total = 0;
			let s= '';
			for (s=''; n!==0; (n>>>=1)) {
				s = ((n&1)?'1':'0') + s;
			}
			const lpad = Math.max(total-s.length, 0);
			if (lpad > 0) {
				for (let i=0; i<lpad; i++)
				{
					s = "0" + s;
				}
			}
			if (s === '')
				return "0";
			return s;
		}

		this.dec2hex = function(n, total) {
			if (total === undefined)
				total = 0;
			let str = n.toString(16);
			const lpad = Math.max(total-str.length, 0);
			if (lpad > 0) {
				for (let i=0; i<lpad; i++)
				{
					str = "0" + str;
				}
			}
			if (str === '')
				return "0";
			return str;
		}

		this.parse_udp = function (IP, hexlist) {
			let UDP = { };
			UDP.srcport = (hexlist[0] << 8) | (hexlist[1] & 0xff);
			UDP.dstport = (hexlist[2] << 8) | (hexlist[3] & 0xff);
			UDP.length = (hexlist[4] << 8) | (hexlist[5] & 0xff);
			UDP.checksum = (hexlist[6] << 8) | (hexlist[7] & 0xff);
			this.setUDPheader(UDP);
		}

		this.parse_tcp = function (IP, hexlist) {
			let TCP = { 'opts': {} };
			let rid = 0;

			TCP.srcport = (hexlist[0] << 8) | (hexlist[1] & 0xff);
			TCP.dstport = (hexlist[2] << 8) | (hexlist[3] & 0xff);
			TCP.seq = (hexlist[4] << 24) | (hexlist[5] << 16) | (hexlist[6] << 8) | hexlist[7];
			TCP.ack = (hexlist[8] << 24) | (hexlist[9] << 16) | (hexlist[10] << 8) | hexlist[11];
			TCP.doff = hexlist[12] >> 4;
			TCP.reserved = (hexlist[12] >> 1) & 0x07;
			TCP.ns = hexlist[12] & 0x01 ? 1 : 0;
			TCP.cwr = hexlist[13] & 0x80 ? 1 : 0;
			TCP.ece = hexlist[13] & 0x40 ? 1 : 0;
			TCP.urg = hexlist[13] & 0x20 ? 1 : 0;
			TCP.ack = hexlist[13] & 0x10 ? 1 : 0;
			TCP.psh = hexlist[13] & 0x08 ? 1 : 0;
			TCP.rst = hexlist[13] & 0x04 ? 1 : 0;
			TCP.syn = hexlist[13] & 0x02 ? 1 : 0;
			TCP.fin = hexlist[13] & 0x01 ? 1 : 0;
			TCP.window = (hexlist[14] << 8) | (hexlist[15] & 0xff);
			TCP.checksum = (hexlist[16] << 8) | (hexlist[17] & 0xff);
			TCP.urgent = (hexlist[18] << 8) | (hexlist[19] & 0xff);

			this.setTCPheader(TCP);

			rid = this.parent.addRule("u32", "0&0x00FF0000>>16=0x" + this.dec2hex(IP.tos));
			this.addItem("IP TOS",				IP.tos,			rid.toString());

			rid = this.parent.addRule("u32", "5&0xff=0x" + this.dec2hex(IP.ttl));
			this.addItem("IP TTL",				IP.ttl,			rid.toString());

			rid = this.parent.addRule("u32", "2&0xffff=0x" + this.dec2hex(IP.identification));
			this.addItem("IP ID",				IP.identification,		rid.toString());

			rid = this.parent.addRule("u32", "3>>0x0d&0x07=0x" + this.dec2hex(IP.flags));
			this.addItem("IP Flags",				IP.flags,		rid.toString());

			rid = this.parent.addRule("u32", "0x0>>0x16&0x3c@4=0x" + this.dec2hex(TCP.seq));
			this.addItem("TCP SEQ",				TCP.seq,		rid.toString());

			rid = this.parent.addRule("u32", "0x0>>0x16&0x3c@8=0x" + this.dec2hex(TCP.ack));
			this.addItem("TCP ACK",				TCP.ack,		rid.toString());

			rid = this.parent.addRule("u32", "0x0>>0x16&0x3c@12&0xFFFF=0x" + this.dec2hex(TCP.window));
			this.addItem("TCP Window",			TCP.window,		rid.toString());

			rid = this.parent.addRule("u32", "0x0>>0x16&0x3c@12>>28&0xff=0x" + this.dec2hex(TCP.doff));
			this.addItem("TCP DOFF",			TCP.doff,		rid.toString());

			const tcplist = hexlist.splice(0,20);
			let cpos = 0;
			let opt_cur = "";
			let opt_size = 0;
			let opt_expect = "TYPE";
			let opt_data = [];
			let opt_data_left = 0;
			let opt_cur_start = 0;
			const tcp_options_end_pos = IP.length + (TCP.doff*4);

			while (cpos < hexlist.length) {
				if (cpos+IP.length+20 > tcp_options_end_pos) {
					// "todo: BAD OPT"
					break;
				}
				if (opt_expect === "TYPE") {
					opt_data_left = 0;
					opt_size = 0;
					opt_cur_start = cpos;
					let mpos;
					switch(hexlist[cpos])
					{
						case 1:
							opt_expect = "TYPE";
							opt_cur = "NOP";
							mpos = 20+opt_cur_start-3;
							rid = this.parent.addRule("u32", "0x0>>0x16&0x3c@"+mpos.toString()+"&0xff=0x01");
							this.addItem("NOP", 1, rid.toString());
							cpos++;
							continue;
							break;
						case 2:
							opt_expect = "SIZE";
							opt_cur = "MSS";
							cpos++;
							continue;
							break;
						case 3:
							opt_expect = "SIZE";
							opt_cur = "WSCALE";
							cpos++;
							continue;
							break;
						case 4:
							opt_expect = "SIZE";
							opt_cur = "SACK";
							mpos = 20+opt_cur_start-2;
							rid = this.parent.addRule("u32", "0x0>>0x16&0x3c@"+mpos.toString()+"&0xffff=0x0402");
							this.addItem("SACKOK",1, rid.toString());
							cpos++;
							continue;
							break;
						case 8:
							opt_expect = "SIZE";
							opt_cur = "TIMESTAMP";
							cpos++;
							continue;
							break;
						case 0:
							opt_expect = "TYPE";
							opt_cur = "EOL";
							mpos = 20+opt_cur_start-3;
							rid = this.parent.addRule("u32", "0x0>>0x16&0x3c@"+mpos.toString()+"&0xff=0x00");
							this.addItem("EOL", 1, rid.toString());
							cpos++;
							continue;
							break;
					}
				} else if (opt_expect === "SIZE") {
					opt_size = hexlist[cpos];
					opt_data_left = opt_size-2;
					cpos++;
					if (opt_size === 2) {
						opt_expect = "TYPE";
					} else {
						opt_expect = "DATA";
						opt_data = [];
					}
					continue;
				} else if (opt_expect === "DATA") {
					let mpos;
					opt_data.push(hexlist[cpos]);
					--opt_data_left;
					if (opt_data_left === 0) {
						opt_expect = "TYPE";
						switch (opt_cur)
						{
							case 'MSS':
								TCP.mss = (opt_data[0] << 8) | (opt_data[1] & 0xff);
								rid = this.parent.addRule("normal", "-m tcpmss --mss "+TCP.mss.toString());
								this.addItem("MSS",				TCP.mss, rid.toString());
								rid = this.parent.addRule("normal", "-m tcpmss --mss "+TCP.mss.toString());
								break;
							case 'WSCALE':
								TCP.wscale = opt_data[0];
								//0x0>>0x16&0x3c@0x25>>0x08 & 0x00ffffff = 0x030307
								mpos = 20+opt_cur_start-1;
								rid = this.parent.addRule("u32", "0x0>>0x16&0x3c@"+mpos.toString()+"&0x00ffffff="+"0x0303"+this.dec2hex(TCP.wscale, 2));
								this.addItem("WSCALE",	TCP.wscale, rid.toString());
								break;
							case 'TIMESTAMP':
								mpos = 20+opt_cur_start;
								const tspos = mpos+2;
								const ecrpos = mpos+6;
								TCP.timestamp = (opt_data[0] << 24) | (opt_data[1] << 16) | (opt_data[2] << 8) | opt_data[3];
								TCP.ecr = (opt_data[4] << 24) | (opt_data[5] << 16) | (opt_data[6] << 8) | opt_data[7];
								rid = this.parent.addRule("u32", "0x0>>0x16&0x3c@"+tspos.toString()+"=0x"+this.dec2hex(TCP.timestamp));
								this.addItem("TS TIMESTAMP",	TCP.timestamp, rid.toString());
								rid = this.parent.addRule("u32", "0x0>>0x16&0x3c@"+ecrpos.toString()+"=0x"+this.dec2hex(TCP.ecr));
								this.addItem("TS ECHO (ECR)",	TCP.ecr, rid.toString());
								break;
						}
					}
					cpos++;
					continue;
				}
				cpos++;
			}
		}

		this.set_parser_response = function (msg) {
			const jmsg = $("#parser-message");
			if (!msg) {
				jmsg.html("");
				return false;
			}
			jmsg.html(msg);
		}

		this.parse = function() {
			this.set_parser_response();

			const PROTO_TCP = 6;
			const PROTO_UDP = 17;

			const txt = document.getElementById('textarea-tcpdump');
			const vv = txt.value.trim();
			const lines = vv.split('\n');

			let hexlist = this.stripHEX(lines);
			if (!hexlist || hexlist.length < 20) {
				this.set_parser_response("Invalid tcpdump input");
				return false;
			}
			let IP = { 'opts': {} };

			IP.version	= hexlist[0] >> 4 & 0x0f;
			IP.tos		= hexlist[1] >> 2;
			IP.length	= (hexlist[0] & 0x0f) << 2;
			IP.total	= (hexlist[2] << 8) | (hexlist[3] & 0xff);
			IP.ecn		= hexlist[1] >> 6;
			IP.ttl		= hexlist[8];
			IP.proto	= hexlist[9];
			IP.src		= hexlist[12].toString()+"."+hexlist[13].toString()+"."+hexlist[14].toString()+"."+hexlist[15].toString();
			IP.dst		= hexlist[16].toString()+"."+hexlist[17].toString()+"."+hexlist[18].toString()+"."+hexlist[19].toString();
			IP.identification = (hexlist[4] << 8) | hexlist[5];
			IP.flags	= hexlist[6] >> 13;
			IP.foff		= hexlist[6] & 0x1fff;
			IP.checksum = (hexlist[10] << 8) | hexlist[11];

			this.setIPheader(IP);


			let iplist = hexlist.splice(0, IP.length);

			if (IP.proto === PROTO_TCP) {
				this.parse_tcp(IP, hexlist);
			} else if (IP.proto === PROTO_UDP) {
				this.parse_udp(IP, hexlist);
			} else {
				this.set_parser_response(`Unknown protocol id: ${IP.proto}`);
			}
		}

		this.register_help = function(tid, hid) {
			const tip4 = document.getElementById(tid);
			const td_all = tip4.getElementsByTagName('TD');
			const td_help = document.getElementById(hid);
			for (let i=0; i<td_all.length; ++i)
			{
				const htxt = td_all[i].getAttribute('data-help');
				if (htxt === undefined)
					continue;
				$(td_all[i]).mouseover(function() {
					td_help.innerHTML= this.getAttribute('data-help');
				});
				$(td_all[i]).mouseout(function() {
					td_help.innerHTML="";
				});
			}
		}

		this.genRule = function() {
			const rr = document.getElementById("rule");
			const ti = document.getElementById("table-iptables");
			const chklist = ti.getElementsByTagName('INPUT');
			let rlist = this.parent.rules;
			rr.value = "";
			let urules = [];
			let nrules = [];
			for (let i=0; i<chklist.length; i++)
			{
				const ci = chklist[i];
				if (ci.type.toLowerCase() === "checkbox") {
					if (ci.checked !== true)
						continue;
					var att = ci.getAttribute("data-rule");
					if (att === undefined)
						continue;
					if (att === "")
						continue;
					var crule = rlist[parseInt(att)];
					if (crule === undefined)
						continue;
					if (crule.type === "u32") {
						urules.push(crule.match);
					} else if (crule.type === "normal") {
						nrules.push(crule.match);
					}
				}
			}
			let totalrule = [];
			if (nrules.length > 0)
				totalrule.push(nrules.join(" "));
			if (urules.length > 0) {
				totalrule.push('-m u32 --u32 "0x6&0xff=0x6 && '+urules.join(" && ")+ '"');
			}
			if (totalrule.length > 0)
				rr.value = totalrule.join(" ");
		}

		this.init = function() {
			const self = this;
			this.register_help('table-ipv4', 'ip-desc');
			this.register_help('table-tcp', 'tcp-desc');
			this.register_help('table-udp', 'udp-desc');
			self.cleanTable();
			$(".button-testdata").click(function (e) {
				const jtextarea = $("#textarea-tcpdump");
				const proto = $(e.target).attr("data-type");
				if (proto === "tcp") {
					jtextarea.val("0x0000:  4510 003c e248 4000 4006 5a61 7f00 0001\n0x0010:  7f00 0001 924a 2bcb 1fdb a858 0000 0000\n0x0020:  a002 ffd7 fe30 0000 0204 ffd7 0402 080a\n0x0030:  98bf 37c6 0000 0000 0103 0307\n");
				} else {
					jtextarea.val("0x0000:  4500 0021 7e1d 4000 4011 beac 7f00 0001\n0x0010:  7f00 0001 e94f 2bcb 000d fe20 7465 7374\n0x0020:  0a\n");
				}
			});
			$("#button-reset").click(function () {
				self.cleanTable();
				self.parent.rules = [];
				self.set_parser_response();
				$("#table-ipv4 TD").each(function (array_it, obj) {
					if (obj.id.length) {
						if (obj.id.match(/-desc$/))
							return;
						obj.innerHTML = "";
					}
				});
				$("#table-tcp TD").each(function (array_it, obj) {
					if (obj.id.length) {
						if (obj.id.match(/-desc$/))
							return;
						obj.innerHTML = "";
					}
				});
				$("#table-udp TD").each(function (array_it, obj) {
					if (obj.id.length) {
						if (obj.id.match(/-desc$/))
							return;
						obj.innerHTML = "";
					}
				});
			});
			$("#button-parser").click( function() {
				self.parent.rules = [];
				self.cleanTable();
				self.parse();
			} );
			$("#button-generate-rule").click( function() {
				self.genRule();
			} );
		}
	})(this);

	this.rules = [];
	this.addRule = function(type, match) {
		const rid = this.rules.length;
		this.rules.push({ "type": type, "match": match});
		return rid;
	}

	this.init = function() {
		const self = this;
		$(document).ready(function() {
			self.UI.init();
		});
	}

	this.init();
});
