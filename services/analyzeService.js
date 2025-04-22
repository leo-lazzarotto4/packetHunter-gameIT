const fs = require('fs');
const pcapParser = require('pcap-parser');

const processPacket = (packet, hostsInfo) => {
  try {
    if (packet.payload && packet.payload.dhcp) {
      processDhcpPacket(packet, hostsInfo);
    }
    if (packet.payload && packet.payload.http && packet.payload.http['accept-language']) {
      processHttpPacket(packet, hostsInfo);
    }
    if (packet.payload && packet.payload.kerberos) {
      processKerberosPacket(packet, hostsInfo);
    }
  } catch (error) {
    console.error("Error processing packet:", error);
  }
};

const processDhcpPacket = (packet, hostsInfo) => {
  try {
    const mac = packet.payload.eth.src;
    let ip = packet.payload.dhcp.ip_your || packet.payload.dhcp.ip_client || packet.payload.ip.src;
    let hostname = packet.payload.dhcp.option_hostname || null;

    if (mac && ip) {
      if (!hostsInfo[mac]) {
        hostsInfo[mac] = { mac, ip, hostname, username: null };
      } else {
        hostsInfo[mac].ip = ip;
        hostsInfo[mac].hostname = hostname || hostsInfo[mac].hostname;
      }
    }
  } catch (error) {
    console.error("Error processing DHCP packet:", error);
  }
};

const processHttpPacket = (packet, hostsInfo) => {
  try {
    const mac = packet.payload.eth.src;
    const ip = packet.payload.ip.src;

    if (mac) {
      if (!hostsInfo[mac]) {
        hostsInfo[mac] = { mac, ip, hostname: null, username: null };
      }
      if (packet.payload.http.cookie) {
        const usernameMatch = packet.payload.http.cookie.match(/username=([^;]+)/);
        if (usernameMatch) {
          hostsInfo[mac].username = usernameMatch[1];
        }
      }
    }
  } catch (error) {
    console.error("Error processing HTTP packet:", error);
  }
};

const processKerberosPacket = (packet, hostsInfo) => {
  try {
    const mac = packet.payload.eth.src;
    const ip = packet.payload.ip.src;

    if (mac) {
      if (!hostsInfo[mac]) {
        hostsInfo[mac] = { mac, ip, hostname: null, username: null };
      }
      if (packet.payload.kerberos.CNameString) {
        const cname = packet.payload.kerberos.CNameString;
        if (cname.endsWith('$')) {
          hostsInfo[mac].hostname = cname;
        } else {
          hostsInfo[mac].username = cname;
        }
      }
    }
  } catch (error) {
    console.error("Error processing Kerberos packet:", error);
  }
};

const analyzePCAP = (filePath) => {
  return new Promise((resolve, reject) => {
    const parser = pcapParser.parse(fs.createReadStream(filePath));
    let packetCount = 0;
    let hostsInfo = {};

    parser.on('packet', (packet) => {
      packetCount++;
      processPacket(packet, hostsInfo);
    });

    parser.on('end', () => {
      const result = Object.values(hostsInfo);
      resolve(result);  // Retourner directement les informations extraites
    });

    parser.on('error', (err) => reject(err));
  });
};

module.exports = analyzePCAP;
