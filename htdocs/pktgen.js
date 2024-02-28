var MAXHISTORY = 60 * 30;
var starttime = 0;
var do_clear = 0;

$(function(event){
	StartConnect(event);
});

function sprintf(str) {
	var spacepad = "                                ";
	var zeropad  = "00000000000000000000000000000000";

	function padout(left, zero, pad, str) {
		if (str.length > pad) {
			return str;
		}
		if (left != '') {
			return (str + spacepad).substr(0, pad);
		}
		return (((zero == '') ? spacepad : zeropad) + str).substr(-pad)
	};

	var fn = {
		d: function(left, zero, pad, value) { return padout(left, zero, pad, value.toString(10)); },
		o: function(left, zero, pad, value) { return padout(left, zero, pad, value.toString(8)); },
		s: padout,
		x: function(left, zero, pad, value) { return padout(left, zero, pad, value.toString(16)); },
	};

	var arg = arguments;
	var n = 1;
	return str.replace(/%(-?)(0*)(\d*)([dosx])/g, function(all, left, zero, pad, type) { return fn[type](left, zero, pad, arg[n++]); });
}

function clearlog(id) {
	document.getElementById(id).value = '';
}

function log(id, logmsg) {
	document.getElementById(id).value =
	    logmsg + document.getElementById(id).value;
}

var connected = 0;
function StopConnect(event, url)
{
	log("log", "stop\n");
	connected = 0;
	starttime = 0;
}

function macaddr(addr)
{
	if (addr == "00:00:00:00:00:00") {
		return "resolving";
	}
	return addr;
}

function UpdateStatus(obj)
{
	var running = obj.time ? "running<br>" : "pktgen is not running<br>";
	var graph = '';

	if (obj.time) {

		graph = sprintf("[%s] %s(%s) &lt;----&gt; %s(%s) [TARGET] %s(%s) &lt;----&gt; %s(%s) [%s]<br>",
		    obj.statistics[0].interface,
		    obj.statistics[0].address,
		    obj.statistics[0].macaddr,
		    obj.statistics[0]["gateway-address"],
		    macaddr(obj.statistics[0]["gateway-macaddr"]),
		    obj.statistics[1]["gateway-address"],
		    macaddr(obj.statistics[1]["gateway-macaddr"]),
		    obj.statistics[1].address,
		    obj.statistics[1].macaddr,
		    obj.statistics[1].interface);
	}

	$("#status").html(
		running + graph
	);
}

function LoopConnection(pps_g, pps_data, drop_g, drop_data, bps_g, bps_data, pktsize_g, pktsize_data)
{
	jQuery.getJSON('/stat/1', function(json) {
		if (connected) {
			if (do_clear) {
				pps_data = [];
				drop_data = [];
				bps_data = [];
				pktsize_data = [];
				do_clear = 0;
			}

//			log('log',
//			    sprintf("%s TX:%d RX:%d\n",
//			        json.statistics[0].interface, json.statistics[0].TX, json.statistics[0].RX));
//			log('log',
//			    sprintf("%s TX:%d RX:%d\n",
//			        json.statistics[1].interface, json.statistics[1].TX, json.statistics[1].RX));

			for (var i = 0; i < 2; i++) {
				log('log',
				    sprintf("%s pktsize:%4d TXbps:%12d RXbps:%12d TXpps:%10d RXpps:%10d\n",
				        json.statistics[i].interface,
				        json.statistics[i].packetsize,
				        json.statistics[i].TXbps, json.statistics[i].RXbps,
				        json.statistics[i].TXpps, json.statistics[i].RXpps));
			}

			var t = json.time;
			if (starttime == 0) {
				starttime = t;
			}
			t -= starttime;

			var tx1pps = json.statistics[0].TXpps;
			var rx1pps = json.statistics[0].RXpps;
			var tx1ppsunder = json.statistics[0].TXunderrun;
			var rx1dropps = json.statistics[0].RXdropps;

			var tx2pps = json.statistics[1].TXpps;
			var rx2pps = json.statistics[1].RXpps;
			var tx2ppsunder = json.statistics[1].TXunderrun;
			var rx2dropps = json.statistics[1].RXdropps;
			pps_data.push([~~t, tx1pps, rx1pps, tx2pps, rx2pps]);
			pps_g.updateOptions( { 'file': pps_data } );

			drop_data.push([~~t, rx1dropps, rx2dropps]);
			drop_g.updateOptions( { 'file': drop_data } );

			var tx1bps = json.statistics[0].TXbps / 1000 / 1000;
			var rx1bps = json.statistics[0].RXbps / 1000 / 1000;
			var tx2bps = json.statistics[1].TXbps / 1000 / 1000;
			var rx2bps = json.statistics[1].RXbps / 1000 / 1000;
			bps_data.push([~~t, tx1bps, rx1bps, tx2bps, rx2bps]);
			bps_g.updateOptions( { 'file': bps_data } );

			var pktsize = json.statistics[1].packetsize;
			pktsize_data.push([~~t, pktsize]);
			pktsize_g.updateOptions( { 'file': pktsize_data } );

			if (pps_data.length > MAXHISTORY) {
				pps_data.splice(0, 1);
			}
			if (bps_data.length > MAXHISTORY) {
				bps_data.splice(0, 1);
			}
			if (pktsize_data.length > MAXHISTORY) {
				pktsize_data.splice(0, 1);
			}

			$("#statistics").html(
			    sprintf(
			        "packet size: %d<br>\n" +
			        "TX: %d<br>\n" +
			        "RX: %d<br>\n" +
			        "RX-Drop: %d<br>\n" +
			        "TX-underrun: %d<br>\n" +
			        "RX-flowcontrol: %d<br>\n",
			        json.statistics[1].packetsize,
			        json.statistics[1].TX,
			        json.statistics[0].RX,
			        json.statistics[0].RXdrop,
			        json.statistics[1].TXunderrun,
			        json.statistics[0].RXflowcontrol)
			);

			UpdateStatus(json);

			LoopConnection(pps_g, pps_data, drop_g, drop_data, bps_g, bps_data, pktsize_g, pktsize_data);
		}
	}).fail(function() {
		log('log', "getJSON failure\n");
		UpdateStatus({});
		setTimeout(function() {
			LoopConnection(pps_g, pps_data, drop_g, drop_data, bps_g, bps_data, pktsize_g, pktsize_data);
		}, 1000);
	});
}

function StartConnect(event, url)
{
	var pps_data = [];
	var drop_data = [];
	var bps_data = [];
	var pktsize_data = [];
	var pps_g = new Dygraph(document.getElementById("pps_g"), pps_data,
		{
			title: 'packet per second',
			drawPoints: true,
			labels: ['Time', 'TX1', 'RX1', 'TX2', 'RX2'],
			ylabel: 'pps',
//			animateZoomes: true,
//			showRangeSelector: true,
			fillGraph: true,
			rangeSelectorHeight: 30,
			rangeSelectorPlotStrokeColor: 'yellow',
			rangeSelectorPlotFilllColor: 'lightyellow'
		}
	);
	var drop_g = new Dygraph(document.getElementById("drop_g"), bps_data,
		{
			title: 'Drop packet per second',
			drawPoints: true,
			labels: ['Time', 'RX1', 'RX2'],
			ylabel: 'drops',
			logscale: true,
//			animateZoomes: true,
//			showRangeSelector: true,
			fillGraph: true,
			rangeSelectorHeight: 30,
			rangeSelectorPlotStrokeColor: 'yellow',
			rangeSelectorPlotFilllColor: 'lightyellow'
		}
	);
	var bps_g = new Dygraph(document.getElementById("bps_g"), bps_data,
		{
			title: 'Mbit per second',
			drawPoints: true,
			labels: ['Time', 'TX1', 'RX1', 'TX2', 'RX2'],
			ylabel: 'Mbps',
//			animateZoomes: true,
//			showRangeSelector: true,
			fillGraph: true,
			rangeSelectorHeight: 30,
			rangeSelectorPlotStrokeColor: 'yellow',
			rangeSelectorPlotFilllColor: 'lightyellow'
		}
	);
	var pktsize_g = new Dygraph(document.getElementById("pktsize_g"), bps_data,
		{
			title: 'packetsize',
			drawPoints: true,
			labels: ['Time', 'PacketSize'],
			ylabel: 'pktsize',
//			animateZoomes: true,
//			showRangeSelector: true,
			fillGraph: true,
			valueRange: [64,1600],
			rangeSelectorHeight: 30,
			rangeSelectorPlotStrokeColor: 'yellow',
			rangeSelectorPlotFilllColor: 'lightyellow'
		}
	);

	log('log', "start\n");
	connected = 1;
	LoopConnection(pps_g, pps_data, drop_g, drop_data, bps_g, bps_data, pktsize_g, pktsize_data);
}

function ClearHistory(event)
{
	do_clear = 1;
}

function ClearStat(event)
{
	var url = sprintf("/clear");
	jQuery.get(url);
}

function SetPacketSize(event, pktsize)
{
	var url = sprintf("/interface/1/pktsize/%d", pktsize);
	jQuery.get(url);
}

function SetPPS(event, pps)
{
	var url = sprintf("/interface/1/pps/%d", pps);
	jQuery.get(url);
}


