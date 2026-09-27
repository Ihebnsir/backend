var dns = require('dns').promises;
var net = require('net');

var blockedIpv4Ranges = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4]
];

function createGuardError(code, message) {
  var error = new Error(message);
  error.code = code;
  return error;
}

function ipv4ToNumber(address) {
  if (net.isIP(address) !== 4) return null;

  return address.split('.').reduce(function(value, part) {
    return value * 256 + Number(part);
  }, 0);
}

function isIpv4InRange(address, network, prefixLength) {
  var addressNumber = ipv4ToNumber(address);
  var networkNumber = ipv4ToNumber(network);
  if (addressNumber === null || networkNumber === null) return false;

  var shift = BigInt(32 - prefixLength);
  return (BigInt(addressNumber) >> shift) === (BigInt(networkNumber) >> shift);
}

function ipv6ToBigInt(address) {
  var normalized = address.toLowerCase();

  if (normalized.indexOf('.') !== -1) {
    var lastColon = normalized.lastIndexOf(':');
    var ipv4Part = normalized.slice(lastColon + 1);
    var ipv4Number = ipv4ToNumber(ipv4Part);
    if (lastColon === -1 || ipv4Number === null) return null;

    var upper = Math.floor(ipv4Number / 65536).toString(16);
    var lower = (ipv4Number % 65536).toString(16);
    normalized = normalized.slice(0, lastColon + 1) + upper + ':' + lower;
  }

  var halves = normalized.split('::');
  if (halves.length > 2) return null;

  var left = halves[0] ? halves[0].split(':') : [];
  var right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  var groups;

  if (halves.length === 2) {
    var missingGroups = 8 - left.length - right.length;
    if (missingGroups < 1) return null;
    groups = left.concat(new Array(missingGroups).fill('0'), right);
  } else {
    groups = left;
  }

  if (groups.length !== 8 || groups.some(function(group) {
    return !/^[0-9a-f]{1,4}$/.test(group);
  })) return null;

  return groups.reduce(function(value, group) {
    return (value << 16n) | BigInt(parseInt(group, 16));
  }, 0n);
}

function isIpv6InRange(addressNumber, network, prefixLength) {
  var networkNumber = ipv6ToBigInt(network);
  if (addressNumber === null || networkNumber === null) return false;

  var shift = BigInt(128 - prefixLength);
  return (addressNumber >> shift) === (networkNumber >> shift);
}

function isPrivateIP(ip) {
  var family = net.isIP(ip);
  if (!family) return true;

  if (family === 4) {
    return blockedIpv4Ranges.some(function(range) {
      return isIpv4InRange(ip, range[0], range[1]);
    });
  }

  var addressNumber = ipv6ToBigInt(ip);
  if (addressNumber === null) return true;

  var mappedIpv4Prefix = ipv6ToBigInt('::ffff:0:0');
  if ((addressNumber >> 32n) === (mappedIpv4Prefix >> 32n)) {
    var mappedIpv4 = Number(addressNumber & 0xffffffffn);
    var mappedAddress = [
      Math.floor(mappedIpv4 / 16777216),
      Math.floor(mappedIpv4 / 65536) % 256,
      Math.floor(mappedIpv4 / 256) % 256,
      mappedIpv4 % 256
    ].join('.');
    return isPrivateIP(mappedAddress);
  }

  var isGlobalUnicast = (addressNumber >> 125n) === 1n;
  if (!isGlobalUnicast) return true;

  return isIpv6InRange(addressNumber, '2001::', 23) ||
    isIpv6InRange(addressNumber, '2001:db8::', 32) ||
    isIpv6InRange(addressNumber, '2001:2::', 48) ||
    isIpv6InRange(addressNumber, '2002::', 16);
}

function isLoopbackAddress(ip) {
  if (ip === '127.0.0.1') return true;
  return net.isIP(ip) === 6 && ipv6ToBigInt(ip) === 1n;
}

async function assertSafeTarget(target) {
  var parsedUrl;
  try {
    if (typeof target !== 'string' || !target.trim()) throw new Error('URL vide');
    parsedUrl = new URL(target);
  } catch (error) {
    throw createGuardError('SSRF_REJECTED', 'Cible non autorisée : URL invalide');
  }

  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    throw createGuardError('SSRF_REJECTED', 'Cible non autorisée : protocole non pris en charge');
  }
  if (parsedUrl.username || parsedUrl.password) {
    throw createGuardError('SSRF_REJECTED', 'Cible non autorisée : identifiants intégrés dans l’URL');
  }

  var hostname = parsedUrl.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  var isLocalhostName = hostname === 'localhost';
  var isAllowedLoopbackIp = hostname === '127.0.0.1';
  var addresses;

  try {
    addresses = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch (error) {
    throw createGuardError('SSRF_DNS_ERROR', 'Cible non autorisée : nom d’hôte impossible à résoudre');
  }

  if (!addresses.length) {
    throw createGuardError('SSRF_DNS_ERROR', 'Cible non autorisée : nom d’hôte impossible à résoudre');
  }

  for (var index = 0; index < addresses.length; index += 1) {
    var address = addresses[index].address;
    var allowedLocalAddress = (isAllowedLoopbackIp && address === '127.0.0.1') ||
      (isLocalhostName && isLoopbackAddress(address));

    // Exception réservée au développement local; elle ne doit jamais être activée dans un produit en production.
    if (allowedLocalAddress) continue;

    if (isPrivateIP(address)) {
      throw createGuardError('SSRF_REJECTED', 'Cible non autorisée : plage d’adresse privée détectée');
    }
  }

  return addresses[0].address;
}

module.exports = {
  assertSafeTarget: assertSafeTarget,
  isPrivateIP: isPrivateIP
};
