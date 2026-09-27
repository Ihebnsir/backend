var ssrfGuard = require('./ssrfGuard');

var requestTimeoutMs = 5000;
var maximumHtmlBytes = 2 * 1024 * 1024;

function createProbeError(code, message) {
  return {
    code: code,
    message: message
  };
}

function failedProbe(error, isHttps) {
  var code = error && error.code ? error.code : 'PROBE_NETWORK_ERROR';
  var message = error && error.message ? error.message : 'La requête vers la cible a échoué';

  return {
    status: null,
    headers: {},
    cookies: [],
    isHttps: Boolean(isHttps),
    redirectNotFollowed: false,
    error: createProbeError(code, message)
  };
}

function getNetworkError(error, timedOut) {
  if (timedOut || (error && error.name === 'AbortError')) {
    return createProbeError('PROBE_TIMEOUT', 'La cible n’a pas répondu dans le délai de 5 secondes');
  }

  if (error && (error.code === 'SSRF_REJECTED' || error.code === 'SSRF_DNS_ERROR')) {
    return createProbeError(error.code, error.message);
  }

  var causeCode = error && error.cause && error.cause.code;
  if (causeCode === 'ENOTFOUND' || causeCode === 'EAI_AGAIN') {
    return createProbeError('PROBE_DNS_ERROR', 'Impossible de résoudre le nom d’hôte de la cible');
  }
  if (causeCode === 'ECONNREFUSED') {
    return createProbeError('PROBE_CONNECTION_REFUSED', 'La connexion à la cible a été refusée');
  }

  return createProbeError('PROBE_NETWORK_ERROR', 'La requête vers la cible a échoué');
}

function responseHeadersToObject(headers) {
  var result = {};
  headers.forEach(function(value, name) {
    result[name.toLowerCase()] = value;
  });
  return result;
}

function getRawCookies(headers) {
  if (typeof headers.getSetCookie === 'function') {
    return headers.getSetCookie();
  }

  var cookieHeader = headers.get('set-cookie');
  return cookieHeader
    ? cookieHeader.split(/,(?=\s*[^;,=\s]+\s*=)/)
    : [];
}

async function fetchHeaders(url, signal) {
  var response = await fetch(url, {
    method: 'GET',
    redirect: 'manual',
    signal: signal
  });

  var result = {
    status: response.status,
    headers: responseHeadersToObject(response.headers),
    cookies: getRawCookies(response.headers),
    body: '',
    bodyTruncated: false
  };

  if (response.body) {
    var contentType = (response.headers.get('content-type') || '').toLowerCase();
    var isHtml = !contentType || contentType.indexOf('text/html') !== -1 || contentType.indexOf('application/xhtml+xml') !== -1;

    if (!isHtml) {
      await response.body.cancel().catch(function() {});
      return result;
    }

    var reader = response.body.getReader();
    var chunks = [];
    var bytesRead = 0;

    try {
      while (true) {
        var part = await reader.read();
        if (part.done) break;

        var remainingBytes = maximumHtmlBytes - bytesRead;
        if (part.value.byteLength > remainingBytes) {
          if (remainingBytes > 0) chunks.push(part.value.slice(0, remainingBytes));
          bytesRead = maximumHtmlBytes;
          result.bodyTruncated = true;
          await reader.cancel();
          break;
        }

        chunks.push(part.value);
        bytesRead += part.value.byteLength;
        if (bytesRead === maximumHtmlBytes) {
          result.bodyTruncated = true;
          await reader.cancel();
          break;
        }
      }

      result.body = Buffer.concat(chunks.map(function(chunk) { return Buffer.from(chunk); })).toString('utf8');
    } catch (error) {
      await reader.cancel().catch(function() {});
    } finally {
      reader.releaseLock();
    }
  }

  return result;
}

function isRedirect(status) {
  return status >= 300 && status < 400;
}

async function probe(target) {
  var controller = new AbortController();
  var timedOut = false;
  var timeout;
  var timeoutPromise = new Promise(function(resolve, reject) {
    timeout = setTimeout(function() {
      timedOut = true;
      controller.abort();
      var error = new Error('Délai maximal de la requête dépassé');
      error.name = 'AbortError';
      reject(error);
    }, requestTimeoutMs);
  });
  var currentUrl;

  try {
    await Promise.race([ssrfGuard.assertSafeTarget(target), timeoutPromise]);
    if (timedOut) return failedProbe(createProbeError('PROBE_TIMEOUT', 'La cible n’a pas répondu dans le délai de 5 secondes'), false);
    currentUrl = new URL(target);

    var response = await Promise.race([fetchHeaders(currentUrl.href, controller.signal), timeoutPromise]);
    var followedRedirect = false;

    while (isRedirect(response.status)) {
      var location = response.headers.location;
      if (!location || followedRedirect) {
        response.redirectNotFollowed = true;
        response.isHttps = currentUrl.protocol === 'https:';
        return response;
      }

      var destination;
      try {
        destination = new URL(location, currentUrl);
        await Promise.race([ssrfGuard.assertSafeTarget(destination.href), timeoutPromise]);
        if (timedOut) throw new Error('Délai maximal de la requête dépassé');
      } catch (error) {
        if (timedOut) throw error;
        response.redirectNotFollowed = true;
        response.redirectBlocked = true;
        response.isHttps = currentUrl.protocol === 'https:';
        return response;
      }

      followedRedirect = true;
      currentUrl = destination;
      response = await Promise.race([fetchHeaders(currentUrl.href, controller.signal), timeoutPromise]);
    }

    response.redirectNotFollowed = false;
    response.isHttps = currentUrl.protocol === 'https:';
    return response;
  } catch (error) {
    var errorInfo = getNetworkError(error, timedOut);
    return failedProbe(errorInfo, currentUrl && currentUrl.protocol === 'https:');
  } finally {
    clearTimeout(timeout);
  }
}

module.exports = { probe: probe };
