import { connect } from 'cloudflare:sockets';

let temporaryTOKEN, permanentTOKEN;

// Define the default export for the Worker
export default {
  async fetch(request, env, ctx) {
    const websiteIcon =
      env.ICO ||
      'https://github.com/user-attachments/assets/31a6ced0-62b8-429f-a98e-082ea5ac1990';
    const url = new URL(request.url);
    const UA = request.headers.get('User-Agent') || 'null';
    const path = url.pathname;
    const hostname = url.hostname;
    const currentDate = new Date();
    const timestamp = Math.ceil(currentDate.getTime() / (1000 * 60 * 31));
    temporaryTOKEN = await doubleHash(url.hostname + timestamp + UA);
    permanentTOKEN = env.TOKEN || temporaryTOKEN;

    if (path.toLowerCase() === '/check') {
      if (!url.searchParams.has('proxyip'))
        return new Response('Missing proxyip parameter', { status: 400 });
      if (url.searchParams.get('proxyip') === '')
        return new Response('Invalid proxyip parameter', { status: 400 });
      if (env.TOKEN) {
        if (!url.searchParams.has('token') || url.searchParams.get('token') !== permanentTOKEN) {
          return new Response(
            JSON.stringify(
              {
                status: 'error',
                message: `ProxyIP Check Failed: Invalid TOKEN`,
                timestamp: new Date().toISOString(),
              },
              null,
              4
            ),
            {
              status: 403,
              headers: {
                'content-type': 'application/json; charset=UTF-8',
                'Access-Control-Allow-Origin': '*',
              },
            }
          );
        }
      }
      const proxyIPInput = url.searchParams.get('proxyip').toLowerCase();
      const result = await CheckProxyIP(proxyIPInput);

      return new Response(JSON.stringify(result, null, 2), {
        status: result.success ? 200 : 502,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      });
    } else if (path.toLowerCase() === '/resolve') {
      if (
        !url.searchParams.has('token') ||
        (url.searchParams.get('token') !== temporaryTOKEN && url.searchParams.get('token') !== permanentTOKEN)
      ) {
        return new Response(
          JSON.stringify(
            {
              status: 'error',
              message: `Domain Resolve Failed: Invalid TOKEN`,
              timestamp: new Date().toISOString(),
            },
            null,
            4
          ),
          {
            status: 403,
            headers: {
              'content-type': 'application/json; charset=UTF-8',
              'Access-Control-Allow-Origin': '*',
            },
          }
        );
      }
      if (!url.searchParams.has('domain'))
        return new Response('Missing domain parameter', { status: 400 });
      const domain = url.searchParams.get('domain');

      try {
        const ips = await resolveDomain(domain);
        return new Response(JSON.stringify({ success: true, domain, ips }), {
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          },
        });
      } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
          status: 500,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
          },
        });
      }
    } else if (path.toLowerCase() === '/ip-info') {
      if (
        !url.searchParams.has('token') ||
        (url.searchParams.get('token') !== temporaryTOKEN && url.searchParams.get('token') !== permanentTOKEN)
      ) {
        return new Response(
          JSON.stringify(
            {
              status: 'error',
              message: `IP Info Failed: Invalid TOKEN`,
              timestamp: new Date().toISOString(),
            },
            null,
            4
          ),
          {
            status: 403,
            headers: {
              'content-type': 'application/json; charset=UTF-8',
              'Access-Control-Allow-Origin': '*',
            },
          }
        );
      }
      let ip = url.searchParams.get('ip') || request.headers.get('CF-Connecting-IP');
      if (!ip) {
        return new Response(
          JSON.stringify(
            {
              status: 'error',
              message: 'IP parameter not provided',
              code: 'MISSING_PARAMETER',
              timestamp: new Date().toISOString(),
            },
            null,
            4
          ),
          {
            status: 400,
            headers: {
              'content-type': 'application/json; charset=UTF-8',
              'Access-Control-Allow-Origin': '*',
            },
          }
        );
      }

      if (ip.includes('[')) {
        ip = ip.replace('[', '').replace(']', '');
      }

      try {
        const response = await fetch(`http://ip-api.com/json/${ip}?lang=en`);
        if (!response.ok) {
          throw new Error(`HTTP error: ${response.status}`);
        }

        const data = await response.json();
        data.timestamp = new Date().toISOString();
        return new Response(JSON.stringify(data, null, 4), {
          headers: {
            'content-type': 'application/json; charset=UTF-8',
            'Access-Control-Allow-Origin': '*',
          },
        });
      } catch (error) {
        console.error('IP Info Fetch Error:', error);
        return new Response(
          JSON.stringify(
            {
              status: 'error',
              message: `IP Info Fetch Error: ${error.message}`,
              code: 'API_REQUEST_FAILED',
              query: ip,
              timestamp: new Date().toISOString(),
              details: {
                errorType: error.name,
                stack: error.stack ? error.stack.split('\n')[0] : null,
              },
            },
            null,
            4
          ),
          {
            status: 500,
            headers: {
              'content-type': 'application/json; charset=UTF-8',
              'Access-Control-Allow-Origin': '*',
            },
          }
        );
      }
    } else {
      const envKey = env.URL302 ? 'URL302' : env.URL ? 'URL' : null;
      if (envKey) {
        const URLs = await sanitizeURLs(env[envKey]);
        const URL = URLs[Math.floor(Math.random() * URLs.length)];
        return envKey === 'URL302' ? Response.redirect(URL, 302) : fetch(new Request(URL, request));
      } else if (env.TOKEN) {
        return new Response(await nginxWelcomePage(), {
          headers: {
            'Content-Type': 'text/html; charset=UTF-8',
          },
        });
      } else if (path.toLowerCase() === '/favicon.ico') {
        return Response.redirect(websiteIcon, 302);
      }
      return await generateHTMLPage(hostname, websiteIcon, temporaryTOKEN);
    }
  },
};

async function resolveDomain(domain) {
  domain = domain.includes(':') ? domain.split(':')[0] : domain;
  try {
    const [ipv4Response, ipv6Response] = await Promise.all([
      fetch(`https://1.1.1.1/dns-query?name=${domain}&type=A`, {
        headers: { Accept: 'application/dns-json' },
      }),
      fetch(`https://1.1.1.1/dns-query?name=${domain}&type=AAAA`, {
        headers: { Accept: 'application/dns-json' },
      }),
    ]);
    const [ipv4Data, ipv6Data] = await Promise.all([ipv4Response.json(), ipv6Response.json()]);

    const ips = [];
    if (ipv4Data.Answer) {
      const ipv4Addresses = ipv4Data.Answer.filter(record => record.type === 1).map(
        record => record.data
      );
      ips.push(...ipv4Addresses);
    }
    if (ipv6Data.Answer) {
      const ipv6Addresses = ipv6Data.Answer.filter(record => record.type === 28).map(
        record => `[${record.data}]`
      );
      ips.push(...ipv6Addresses);
    }
    if (ips.length === 0) {
      throw new Error('No A or AAAA records found');
    }
    return ips;
  } catch (error) {
    throw new Error(`DNS resolution failed: ${error.message}`);
  }
}

async function CheckProxyIP(proxyIP) {
  let portRemote = 443;
  let hostToCheck = proxyIP;
  if (proxyIP.includes('.tp')) {
    const portMatch = proxyIP.match(/\.tp(\d+)\./);
    if (portMatch) portRemote = parseInt(portMatch[1]);
    hostToCheck = proxyIP.split('.tp')[0];
  } else if (proxyIP.includes('[') && proxyIP.includes(']:')) {
    portRemote = parseInt(proxyIP.split(']:')[1]);
    hostToCheck = proxyIP.split(']:')[0] + ']';
  } else if (proxyIP.includes(':') && !proxyIP.startsWith('[')) {
    const parts = proxyIP.split(':');
    if (parts.length === 2 && parts[0].includes('.')) {
      hostToCheck = parts[0];
      portRemote = parseInt(parts[1]) || 443;
    }
  }

  const tcpSocket = connect({
    hostname: hostToCheck,
    port: portRemote,
  });
  try {
    const httpRequest =
      'GET /cdn-cgi/trace HTTP/1.1\r\n' +
      'Host: speed.cloudflare.com\r\n' +
      'User-Agent: checkip/diana/\r\n' +
      'Connection: close\r\n\r\n';
    const writer = tcpSocket.writable.getWriter();
    await writer.write(new TextEncoder().encode(httpRequest));
    writer.releaseLock();

    const reader = tcpSocket.readable.getReader();
    let responseData = new Uint8Array(0);
    while (true) {
      const { value, done } = await Promise.race([
        reader.read(),
        new Promise(resolve => setTimeout(() => resolve({ done: true }), 5000)),
      ]);
      if (done) break;
      if (value) {
        const newData = new Uint8Array(responseData.length + value.length);
        newData.set(responseData);
        newData.set(value, responseData.length);
        responseData = newData;
        const responseText = new TextDecoder().decode(responseData);
        if (
          responseText.includes('\r\n\r\n') &&
          (responseText.includes('Connection: close') || responseText.includes('content-length'))
        ) {
          break;
        }
      }
    }
    reader.releaseLock();

    const responseText = new TextDecoder().decode(responseData);
    const statusMatch = responseText.match(/^HTTP\/\d\.\d\s+(\d+)/i);
    const statusCode = statusMatch ? parseInt(statusMatch[1]) : null;
    function isValidProxyResponse(responseText, responseData) {
      const statusMatch = responseText.match(/^HTTP\/\d\.\d\s+(\d+)/i);
      const statusCode = statusMatch ? parseInt(statusMatch[1]) : null;
      const looksLikeCloudflare = responseText.includes('cloudflare');
      const isExpectedError =
        responseText.includes('plain HTTP request') ||
        responseText.includes('400 Bad Request');
      const hasBody = responseData.length > 100;
      return statusCode !== null && looksLikeCloudflare && isExpectedError && hasBody;
    }
    const isSuccessful = isValidProxyResponse(responseText, responseData);

    const jsonResponse = {
      success: isSuccessful,
      proxyIP: hostToCheck,
      portRemote: portRemote,
      statusCode: statusCode || null,
      responseSize: responseData.length,
      timestamp: new Date().toISOString(),
    };
    await tcpSocket.close();
    return jsonResponse;
  } catch (error) {
    return {
      success: false,
      proxyIP: hostToCheck,
      portRemote: portRemote,
      timestamp: new Date().toISOString(),
      error: error.message || error.toString(),
    };
  }
}

async function sanitizeURLs(content) {
  var replacedContent = content.replace(/[\r\n]+/g, '|').replace(/\|+/g, '|');
  const addressArray = replacedContent.split('|');
  const sanitizedArray = addressArray.filter((item, index) => {
    return item !== '' && addressArray.indexOf(item) === index;
  });
  return sanitizedArray;
}

async function doubleHash(text) {
  const encoder = new TextEncoder();
  const firstHash = await crypto.subtle.digest('MD5', encoder.encode(text));
  const firstHashArray = Array.from(new Uint8Array(firstHash));
  const firstHex = firstHashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
  const secondHash = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
  const secondHashArray = Array.from(new Uint8Array(secondHash));
  const secondHex = secondHashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
  return secondHex.toLowerCase();
}

async function nginxWelcomePage() {
  const text = `
    <!DOCTYPE html>
    <html>
    <head>
    <title>Welcome to nginx!</title>
    <style>
        body {
            width: 35em;
            margin: 0 auto;
            font-family: Tahoma, Verdana, Arial, sans-serif;
        }
    </style>
    </head>
    <body>
    <h1>Welcome to nginx!</h1>
    <p>If you see this page, the nginx web server is successfully installed and
    working. Further configuration is required.</p>
    <p>For online documentation and support please refer to
    <a href="http://nginx.org/">nginx.org</a>.<br/>
    Commercial support is available at
    <a href="http://nginx.com/">nginx.com</a>.</p>
    <p><em>Thank you for using nginx.</em></p>
    </body>
    </html>
  `;
  return text;
}

async function generateHTMLPage(hostname, websiteIcon, token) {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ProxyIP Verifier</title>
  <link rel="icon" href="${websiteIcon}" type="image/x-icon">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;700&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {
      --bg-primary: #0a0a0b;
      --bg-secondary: rgba(30, 41, 59, 0.8);
      --text-primary: #e2e8f0;
      --text-secondary: #94a3b8;
      --accent: #3b82f6;
      --accent-gradient: linear-gradient(135deg, #3b82f6, #8b5cf6);
      --success: #22c55e;
      --error: #ef4444;
      --warning: #f59e0b;
      --border-radius: 12px;
      --shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
      --glass-bg: rgba(255, 255, 255, 0.05);
    }
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }
    body {
      font-family: 'Inter', sans-serif;
      background: var(--bg-primary) url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 1000" width="1000" height="1000"><defs><radialGradient id="bg-grad"><stop offset="0%" stop-color="%23b3e5fc" stop-opacity="0.1"/><stop offset="100%" stop-color="%230a0a0b" stop-opacity="0.3"/></radialGradient></defs><rect width="1000" height="1000" fill="url(%23bg-grad)"/></svg>') no-repeat center/cover fixed;
      color: var(--text-primary);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 20px;
    }
    .container {
      max-width: 1000px;
      width: 100%;
      margin: 0 auto;
    }
    .header {
      text-align: center;
      padding: 3rem 0;
      animation: fadeIn 1s ease-out;
    }
    .header h1 {
      font-size: 3rem;
      font-weight: 700;
      background: var(--accent-gradient);
      -webkit-background-clip: text;
      color: transparent;
      margin-bottom: 0.5rem;
    }
    .header p {
      color: var(--text-secondary);
      font-size: 1.2rem;
      max-width: 500px;
      margin: 0 auto;
    }
    .card {
      background: var(--bg-secondary);
      backdrop-filter: blur(10px);
      border-radius: var(--border-radius);
      padding: 2rem;
      margin: 2rem 0;
      box-shadow: var(--shadow);
      animation: slideUp 0.5s ease-out;
    }
    .form-section {
      display: grid;
      gap: 1.5rem;
    }
    .form-group {
      position: relative;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }
    .form-label {
      font-weight: 500;
      color: var(--text-secondary);
      font-size: 1rem;
      display: flex;
      align-items: center;
      gap: 0.3rem;
    }
    .tooltip {
      cursor: help;
      font-size: 0.8rem;
      color: var(--accent);
    }
    .tooltip:hover::after {
      content: attr(title);
      position: absolute;
      background: var(--bg-secondary);
      color: var(--text-primary);
      padding: 0.5rem;
      border-radius: 6px;
      font-size: 0.8rem;
      z-index: 10;
      top: 100%;
      left: 0;
      white-space: nowrap;
    }
    .form-input {
      padding: 0.9rem 1.2rem;
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 8px;
      background: var(--glass-bg);
      color: var(--text-primary);
      font-size: 1rem;
      transition: all 0.3s ease;
    }
    .form-input:focus {
      outline: none;
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
    }
    .form-input::placeholder {
      color: #64748b;
    }
    .input-icon {
      position: absolute;
      right: 1rem;
      top: 50%;
      transform: translateY(-50%);
      color: var(--text-secondary);
      font-size: 1.2rem;
    }
    .btn-primary {
      background: var(--accent-gradient);
      color: white;
      padding: 1rem;
      border: none;
      border-radius: 8px;
      font-size: 1.1rem;
      font-weight: 600;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    .btn-primary:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 20px rgba(59, 130, 246, 0.3);
    }
    .btn-primary:disabled {
      background: #4b5563;
      cursor: not-allowed;
      transform: none;
      box-shadow: none;
    }
    .loading-spinner {
      width: 18px;
      height: 18px;
      border: 3px solid rgba(255, 255, 255, 0.3);
      border-top-color: white;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    .result-section {
      margin-top: 2rem;
      display: none;
    }
    .result-card {
      background: var(--glass-bg);
      border-radius: 8px;
      padding: 1.5rem;
      margin-bottom: 1rem;
      transition: transform 0.3s ease, opacity 0.3s ease;
      animation: slideUp 0.5s ease-out;
    }
    .result-card:hover {
      transform: translateY(-5px);
    }
    .result-success {
      border-left: 5px solid var(--success);
    }
    .result-error {
      border-left: 5px solid var(--error);
    }
    .result-warning {
      border-left: 5px solid var(--warning);
    }
    .result-card h3 {
      font-size: 1.3rem;
      margin-bottom: 0.8rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .status-icon-prefix {
      font-size: 1.5rem;
    }
    .result-card p {
      color: var(--text-secondary);
      margin: 0.5rem 0;
    }
    .result-card p strong {
      color: var(--text-primary);
    }
    .copy-btn {
      background: var(--glass-bg);
      border: 1px solid var(--text-secondary);
      color: var(--text-secondary);
      padding: 0.3rem 0.8rem;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.9rem;
      margin-left: 0.5rem;
      transition: all 0.2s ease;
    }
    .copy-btn:hover {
      background: var(--accent);
      color: white;
      border-color: var(--accent);
    }
    .toast {
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: var(--bg-secondary);
      color: var(--text-primary);
      padding: 1rem 1.5rem;
      border-radius: 8px;
      box-shadow: var(--shadow);
      z-index: 1000;
      opacity: 0;
      transform: translateY(20px);
      transition: opacity 0.3s ease, transform 0.3s ease;
    }
    .toast.show {
      opacity: 1;
      transform: translateY(0);
    }
    .api-docs {
      margin-top: 2rem;
      padding: 1.5rem;
      background: var(--bg-secondary);
      border-radius: var(--border-radius);
      box-shadow: var(--shadow);
      cursor: pointer;
      transition: all 0.3s ease;
    }
    .api-docs.collapsed .api-content {
      max-height: 0;
      opacity: 0;
      padding: 0;
    }
    .api-docs .api-content {
      max-height: 500px;
      opacity: 1;
      transition: all 0.3s ease;
      padding-top: 1rem;
    }
    .api-docs h3 {
      font-size: 1.3rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .api-docs h3::after {
      content: '▼';
      font-size: 0.9rem;
      transition: transform 0.3s ease;
    }
    .api-docs.collapsed h3::after {
      transform: rotate(-180deg);
    }
    .api-docs p code {
      background: var(--glass-bg);
      padding: 0.3rem 0.6rem;
      border-radius: 6px;
      font-family: monospace;
      color: var(--text-primary);
    }
    .footer {
      text-align: center;
      padding: 2rem 0;
      color: var(--text-secondary);
      font-size: 0.95rem;
      margin-top: auto;
    }
    .footer a {
      color: var(--accent);
      text-decoration: none;
      font-weight: 600;
      transition: color 0.2s ease;
    }
    .footer a:hover {
      color: #8b5cf6;
    }
    .progress-bar {
      width: 100%;
      height: 6px;
      background: var(--glass-bg);
      border-radius: 3px;
      overflow: hidden;
      margin-top: 1rem;
      display: none;
    }
    .progress-fill {
      height: 100%;
      background: var(--accent-gradient);
      width: 0;
      transition: width 0.3s ease;
    }
    .ip-grid {
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }
    .ip-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 0.5rem;
      border-radius: 6px;
      background: var(--glass-bg);
    }
    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }
    @keyframes slideUp {
      from { transform: translateY(20px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }
    @media (max-width: 768px) {
      .header h1 { font-size: 2rem; }
      .header p { font-size: 1rem; }
      .card { padding: 1.5rem; margin: 1rem 0.5rem; }
      .form-input { padding: 0.7rem 1rem; font-size: 0.95rem; }
      .btn-primary { padding: 0.8rem; font-size: 1rem; }
      .result-card h3 { font-size: 1.2rem; }
      .toast { left: 1rem; right: 1rem; bottom: 1rem; }
      .ip-grid { font-size: 0.9rem; }
      .ip-item { flex-direction: column; align-items: flex-start; gap: 0.5rem; }
      .ip-item > div { margin-bottom: 0.3rem; }
      .ip-item .copy-btn { margin-left: 0; }
    }
    @media (min-width: 769px) {
      .form-section { grid-template-columns: 1fr 1fr; }
      .form-group:last-child { grid-column: span 2; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header class="header">
      <h1>ProxyIP Verifier</h1>
      <p>Validate IPs and domains with lightning speed and precision</p>
    </header>

    <div class="card">
      <div class="form-section">
        <div class="form-group">
          <label class="form-label" for="proxyip">
            Single IP / Domain
            <span class="tooltip" title="Enter an IP (e.g., 127.0.0.1:443) or domain (e.g., nima.nscl.ir)">ℹ️</span>
          </label>
          <div class="input-wrapper">
            <input type="text" id="proxyip" class="form-input" placeholder="127.0.0.1:443 or nima.nscl.ir" autocomplete="off">
            <span class="input-icon">🌐</span>
          </div>
        </div>
        
        <div class="form-group">
          <label class="form-label" for="proxyipRange">
            IP Range
            <span class="tooltip" title="Enter a range (e.g., 127.0.0.0/24 or 127.0.0.1-255)">ℹ️</span>
          </label>
          <div class="input-wrapper">
            <input type="text" id="proxyipRange" class="form-input" placeholder="127.0.0.0/24 or 127.0.0.1-255" autocomplete="off">
            <span class="input-icon">📍</span>
          </div>
        </div>

        <div class="form-group">
          <button id="checkBtn" class="btn-primary" onclick="checkInputs()">
            <span class="btn-text">Verify Now</span>
            <span class="loading-spinner" style="display: none;"></span>
          </button>
        </div>
      </div>
      
      <div id="result" class="result-section"></div>
      <div id="rangeResultCard" class="result-card result-section" style="display:none;">
        <h3><span id="rangeResultIcon" class="status-icon-prefix"></span> Successful IPs in Range</h3>
        <div class="progress-bar" id="rangeProgressBar">
          <div class="progress-fill" id="rangeProgressFill"></div>
        </div>
        <div id="rangeResultChartContainer" style="width:100%; max-height:400px; margin: 1.5rem auto; overflow-x: auto;">
          <canvas id="rangeSuccessChart"></canvas>
        </div>
        <div id="rangeResultSummary" style="margin-bottom: 1rem;"></div>
        <button id="copyRangeBtn" class="copy-btn" onclick="copySuccessfulRangeIPs()" style="display:none;">Copy Successful IPs</button>
      </div>
    </div>
    
    <div class="api-docs collapsed" id="apiDocs">
      <h3>API Documentation</h3>
      <div class="api-content">
        <p><code>GET /check?proxyip=YOUR_PROXY_IP&token=YOUR_TOKEN</code></p>
        <p><code>GET /resolve?domain=YOUR_DOMAIN&token=YOUR_TOKEN</code></p>
        <p><code>GET /ip-info?ip=TARGET_IP&token=YOUR_TOKEN</code></p>
      </div>
    </div>

    <footer class="footer">
      <p>Created by <a href="https://github.com/Argh94" target="_blank">Argh94</a></p>
    </footer>
  </div>

  <div id="toast" class="toast"></div>

  <script>
    let isChecking = false;
    const ipCheckResults = new Map();
    let pageLoadTimestamp;
    const TEMP_TOKEN = "${token}";
    let rangeChartInstance = null;
    let currentSuccessfulRangeIPs = [];

    function calculateTimestamp() {
      const currentDate = new Date();
      return Math.ceil(currentDate.getTime() / (1000 * 60 * 13));
    }
    
    document.addEventListener('DOMContentLoaded', () => {
      pageLoadTimestamp = calculateTimestamp();
      const singleIpInput = document.getElementById('proxyip');
      const rangeIpInput = document.getElementById('proxyipRange');
      const apiDocs = document.getElementById('apiDocs');
      
      singleIpInput.focus();
      
      const urlParams = new URLSearchParams(window.location.search);
      let autoCheckValue = urlParams.get('autocheck');
      if (!autoCheckValue) {
        const currentPath = window.location.pathname;
        if (currentPath.length > 1) {
          const pathContent = decodeURIComponent(currentPath.substring(1));
          if (isValidProxyIPFormat(pathContent)) {
            autoCheckValue = pathContent;
          }
        }
      }

      if (autoCheckValue) {
        singleIpInput.value = autoCheckValue;
        const newUrl = new URL(window.location);
        newUrl.searchParams.delete('autocheck');
        newUrl.pathname = '/';
        window.history.replaceState({}, '', newUrl);
        setTimeout(() => { if (!isChecking) checkInputs(); }, 500);
      } else {
        try {
          const lastSearch = localStorage.getItem('lastProxyIP');
          if (lastSearch) singleIpInput.value = lastSearch;
        } catch (e) { console.error('localStorage read error:', e); }
      }
      
      singleIpInput.addEventListener('keypress', e => { if (e.key === 'Enter' && !isChecking) checkInputs(); });
      rangeIpInput.addEventListener('keypress', e => { if (e.key === 'Enter' && !isChecking) checkInputs(); });
      document.addEventListener('click', e => {
        if (e.target.classList.contains('copy-btn')) {
          const text = e.target.getAttribute('data-copy');
          if (text) copyToClipboard(text, e.target);
        }
      });

      apiDocs.addEventListener('click', () => {
        apiDocs.classList.toggle('collapsed');
      });

      apiDocs.querySelector('.api-content').addEventListener('click', e => e.stopPropagation());
    });

    function showToast(message, duration = 3000) {
      const toast = document.getElementById('toast');
      toast.textContent = message;
      toast.classList.add('show');
      setTimeout(() => toast.classList.remove('show'), duration);
    }

    function copyToClipboard(text, element, successMessage = "Copied!") {
      navigator.clipboard.writeText(text).then(() => {
        const originalText = element ? element.textContent : '';
        if (element) element.textContent = '✓ Copied';
        showToast(successMessage);
        if (element) setTimeout(() => { element.textContent = originalText; }, 2000);
      }).catch(err => { showToast('Copy failed. Please copy manually.'); });
    }
    
    function createCopyButton(text) { return \`<span class="copy-btn" data-copy="\${text}">\${text}</span>\`; }

    function isValidProxyIPFormat(input) {
      const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?)*$/;
      const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      const ipv6Regex = /^\\[?([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\\]?$/;
      const withPortRegex = /^.+:\\d+$/;
      const tpPortRegex = /^.+\\.tp\\d+\\./;
      return domainRegex.test(input) || ipv4Regex.test(input) || ipv6Regex.test(input) || withPortRegex.test(input) || tpPortRegex.test(input);
    }
    function isIPAddress(input) {
      const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      const ipv6Regex = /^\\[?([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\\]?$/;
      const ipv6WithPortRegex = /^\\[[0-9a-fA-F:]+\\]:\\d+$/;
      const ipv4WithPortRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):\\d+$/;
      return ipv4Regex.test(input) || ipv6Regex.test(input) || ipv6WithPortRegex.test(input) || ipv4WithPortRegex.test(input);
    }

    function parseIPRange(rangeInput) {
      const ips = [];
      rangeInput = rangeInput.trim();
      if (/^(\\d{1,3}\\.){3}\\d{1,3}\\/24$/.test(rangeInput)) {
        const baseIp = rangeInput.split('/')[0];
        const baseParts = baseIp.split('.');
        if (baseParts.length === 4 ) {
          for (let i = 1; i <= 255; i++) {
            ips.push(\`\${baseParts[0]}.\${baseParts[1]}.\${baseParts[2]}.\${i}\`);
          }
        } else {
          showToast('Invalid CIDR format. Expected x.x.x.0/24.');
        }
      } 
      else if (/^(\\d{1,3}\\.){3}\\d{1,3}-\\d{1,3}$/.test(rangeInput)) {
        const parts = rangeInput.split('-');
        const baseIpWithLastOctet = parts[0];
        const endOctet = parseInt(parts[1]);
        
        const ipParts = baseIpWithLastOctet.split('.');
        if (ipParts.length === 4) {
          const startOctet = parseInt(ipParts[3]);
          const prefix = \`\${ipParts[0]}.\${ipParts[1]}.\${ipParts[2]}\`;
          if (!isNaN(startOctet) && !isNaN(endOctet) && startOctet <= endOctet && startOctet >= 0 && endOctet <= 255) {
            for (let i = startOctet; i <= endOctet; i++) {
              ips.push(\`\${prefix}.\${i}\`);
            }
          } else {
            showToast('Invalid range in x.x.x.A-B format.');
          }
        } else {
          showToast('Invalid x.x.x.A-B range format.');
        }
      }
      return ips;
    }
    
    function preprocessInput(input) {
      if (!input) return input;
      let processed = input.trim();
      if (processed.includes(' ')) {
        processed = processed.split(' ')[0];
      }
      return processed;
    }

    async function checkInputs() {
      if (isChecking) return;
      const singleIpInputEl = document.getElementById('proxyip');
      const rangeIpInputEl = document.getElementById('proxyipRange');
      const resultDiv = document.getElementById('result');
      const rangeResultCard = document.getElementById('rangeResultCard');
      const rangeResultSummary = document.getElementById('rangeResultSummary');
      const copyRangeBtn = document.getElementById('copyRangeBtn');
      const rangeResultIconEl = document.getElementById('rangeResultIcon');

      const checkBtn = document.getElementById('checkBtn');
      const btnText = checkBtn.querySelector('.btn-text');
      const spinner = checkBtn.querySelector('.loading-spinner');
      
      const rawSingleInput = singleIpInputEl.value;
      let singleIpToTest = preprocessInput(rawSingleInput);
      
      const rawRangeInput = rangeIpInputEl.value;
      let rangeIpToTest = preprocessInput(rawRangeInput);
      if (singleIpToTest && singleIpToTest !== rawSingleInput) {
        singleIpInputEl.value = singleIpToTest;
        showToast('Single IP input auto-corrected.');
      }
      if (rangeIpToTest && rangeIpToTest !== rawRangeInput) {
        rangeIpInputEl.value = rangeIpToTest;
        showToast('IP Range input auto-corrected.');
      }

      if (!singleIpToTest && !rangeIpToTest) {
        showToast('Please enter a single IP/Domain or an IP Range.');
        singleIpInputEl.focus();
        return;
      }
      
      const currentTimestamp = calculateTimestamp();
      if (currentTimestamp !== pageLoadTimestamp) {
        const currentHost = window.location.host;
        const currentProtocol = window.location.protocol;
        let redirectPathVal = singleIpToTest || rangeIpToTest || '';
        const redirectUrl = \`\${currentProtocol}//\${currentHost}/\${encodeURIComponent(redirectPathVal)}\`;
        showToast('TOKEN expired, refreshing page...');
        setTimeout(() => { window.location.href = redirectUrl; }, 1000);
        return;
      }

      if (singleIpToTest) {
        try { localStorage.setItem('lastProxyIP', singleIpToTest);
        } catch (e) {}
      }
      
      isChecking = true;
      checkBtn.disabled = true;
      btnText.style.display = 'none';
      spinner.style.display = 'inline-block';
      
      resultDiv.innerHTML = '';
      resultDiv.classList.remove('show');
      rangeResultCard.style.display = 'none';
      rangeResultCard.className = 'result-card result-section';
      if(rangeResultIconEl) rangeResultIconEl.textContent = '';

      rangeResultSummary.innerHTML = '';
      copyRangeBtn.style.display = 'none';
      currentSuccessfulRangeIPs = [];
      if (rangeChartInstance) {
        rangeChartInstance.destroy();
        rangeChartInstance = null;
      }

      try {
        if (singleIpToTest) {
          if (isIPAddress(singleIpToTest)) {
            await checkAndDisplaySingleIP(singleIpToTest, resultDiv);
          } else { 
            await checkAndDisplayDomain(singleIpToTest, resultDiv);
          }
        }

        if (rangeIpToTest) {
          const ipsInRange = parseIPRange(rangeIpToTest);
          if (ipsInRange.length > 0) {
            showToast(\`Starting test for \${ipsInRange.length} IPs in range... This may take a while.\`);
            rangeResultCard.style.display = 'block';
            rangeResultCard.classList.add('result-warning');
            if(rangeResultIconEl) rangeResultIconEl.innerHTML = '⟳';

            let successCount = 0;
            let checkedCount = 0;
            currentSuccessfulRangeIPs = [];

            const batchSize = 10;
            for (let i = 0; i < ipsInRange.length; i += batchSize) {
              const batch = ipsInRange.slice(i, i + batchSize);
              const batchPromises = batch.map(ip => 
                fetchSingleIPCheck(ip + ':443') 
                  .then(data => {
                    checkedCount++;
                    if (data.success) {
                      successCount++;
                      currentSuccessfulRangeIPs.push(data.proxyIP);
                    }
                    return data; 
                  })
                  .catch(err => {
                    checkedCount++; 
                    console.error("Error checking IP in range:", ip, err);
                    return {success: false, proxyIP: ip, error: err.message};
                  })
              );
              await Promise.all(batchPromises);
              rangeResultSummary.innerHTML = \`Tested: \${checkedCount}/\${ipsInRange.length} | Successful: \${successCount}\`;
              
              if (currentSuccessfulRangeIPs.length > 0) {
                updateRangeSuccessChart(currentSuccessfulRangeIPs);
                copyRangeBtn.style.display = 'inline-block';
              } else {
                copyRangeBtn.style.display = 'none';
              }
              if (i + batchSize < ipsInRange.length) {
                await new Promise(resolve => setTimeout(resolve, 200));
              }
            }
            rangeResultSummary.innerHTML = \`Range test complete. \${successCount} of \${ipsInRange.length} IPs were successful.\`;
            rangeResultCard.classList.remove('result-warning');
            if (successCount === ipsInRange.length && ipsInRange.length > 0) {
              rangeResultCard.classList.add('result-success');
              if(rangeResultIconEl) rangeResultIconEl.innerHTML = '<span class="status-icon-prefix success">✔</span>';
            } else if (successCount > 0) {
              rangeResultCard.classList.add('result-warning');
              if(rangeResultIconEl) rangeResultIconEl.innerHTML = '<span class="status-icon-prefix warning">⚠</span>';
            } else {
              rangeResultCard.classList.add('result-error');
              if(rangeResultIconEl) rangeResultIconEl.innerHTML = '<span class="status-icon-prefix error">✖</span>';
              showToast('No successful IPs found in the range.');
            }
          } else if (rangeIpToTest) { 
            showToast('Invalid IP Range format or empty range.');
            rangeResultCard.style.display = 'block';
            rangeResultCard.classList.add('result-error');
            if(rangeResultIconEl) rangeResultIconEl.innerHTML = '<span class="status-icon-prefix error">✖</span>';
            rangeResultSummary.innerHTML = 'Invalid IP Range format provided.';
          }
        }
      } catch (err) {
        const errorMsg = \`<div class="result-card result-error"><h3><span class="status-icon-prefix error">✖</span> General Error</h3><p>\${err.message}</p></div>\`;
        if(resultDiv.innerHTML === '') resultDiv.innerHTML = errorMsg;
        else {
          rangeResultSummary.innerHTML = \`<p>Error during range test: \${err.message}</p>\`;
          rangeResultCard.className = 'result-card result-section result-error';
          if(rangeResultIconEl) rangeResultIconEl.innerHTML = '<span class="status-icon-prefix error">✖</span>';
        }
        if (resultDiv.innerHTML !== '') resultDiv.classList.add('show');
        if (rangeIpToTest) rangeResultCard.style.display = 'block';
      } finally {
        isChecking = false;
        checkBtn.disabled = false;
        btnText.style.display = 'inline-block';
        spinner.style.display = 'none';
      }
    }
    
    function updateRangeSuccessChart(successfulIPs) {
      const ctx = document.getElementById('rangeSuccessChart').getContext('2d');
      if (rangeChartInstance) {
        rangeChartInstance.destroy();
      }
      
      const labels = successfulIPs;
      const dataPoints = successfulIPs.map(() => 1); 
      
      const textColor = getComputedStyle(document.documentElement).getPropertyValue('--text-secondary').trim() || '#cbd5e1';
      const gridBorderColor = '#475569';
      const accentColor = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() || '#3b82f6';
      const accentColorBg = accentColor + '99';

      rangeChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
          labels: labels,
          datasets: [{
            label: 'Successful IPs',
            data: dataPoints,
            backgroundColor: accentColorBg, 
            borderColor: accentColor,
            borderWidth: 1
          }]
        },
        options: {
          indexAxis: 'y',
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: {
              beginAtZero: true,
              ticks: {
                stepSize: 1,
                callback: function(value) { if (value === 1) return 'Success'; return ''; },
                color: textColor
              },
              title: { display: false },
              grid: { color: gridBorderColor }
            },
            y: {
              ticks: {
                autoSkip: false, 
                color: textColor
              },
              title: {
                display: true,
                text: 'IP Addresses',
                color: textColor
              },
              grid: { color: gridBorderColor }
            }
          },
          plugins: {
            legend: {
              display: false,
              labels: { color: textColor }
            },
            tooltip: {
              titleColor: getComputedStyle(document.documentElement).getPropertyValue('--text-primary').trim(),
              bodyColor: textColor,
              backgroundColor: getComputedStyle(document.documentElement).getPropertyValue('--bg-secondary').trim(),
              borderColor: gridBorderColor,
              borderWidth: 1,
              callbacks: {
                label: function(context) {
                  return \`IP: \${context.label} - Status: Successful\`;
                },
                title: function() { return ''; }
              }
            }
          }
        }
      });
      const canvas = document.getElementById('rangeSuccessChart');
      const barHeight = 25;
      const newHeight = Math.max(200, labels.length * barHeight);
      canvas.style.height = \`\${newHeight}px\`;
      if(rangeChartInstance) rangeChartInstance.resize();
    }
    
    function copySuccessfulRangeIPs() {
      if (currentSuccessfulRangeIPs.length > 0) {
        const textToCopy = currentSuccessfulRangeIPs.join('\\n');
        copyToClipboard(textToCopy, null, "All successful IPs copied!");
      } else {
        showToast("No successful IPs to copy.");
      }
    }

    async function fetchSingleIPCheck(proxyipWithOptionalPort) {
      const requestUrl = \`./check?proxyip=\${encodeURIComponent(proxyipWithOptionalPort)}&token=\${TEMP_TOKEN}\`;
      const response = await fetch(requestUrl);
      return await response.json();
    }

    async function checkAndDisplaySingleIP(proxyip, resultDiv) {
      const data = await fetchSingleIPCheck(proxyip);
      if (data.success) {
        const ipInfo = await getIPInfo(data.proxyIP);
        const ipInfoHTML = formatIPInfo(ipInfo);
        resultDiv.innerHTML = \`
          <div class="result-card result-success">
            <h3><span class="status-icon-prefix">✔</span> ProxyIP Valid</h3>
            <p><strong>ProxyIP Address:</strong> \${createCopyButton(data.proxyIP)} \${ipInfoHTML}</p>
            <p><strong>Port:</strong> \${createCopyButton(data.portRemote.toString())}</p>
            <p><strong>Check Time:</strong> \${new Date(data.timestamp).toLocaleString()}</p>
          </div>
        \`;
      } else {
        resultDiv.innerHTML = \`
          <div class="result-card result-error">
            <h3><span class="status-icon-prefix">✖</span> ProxyIP Invalid</h3>
            <p><strong>IP Address:</strong> \${createCopyButton(proxyip)}</p>
            \${data.error ? \`<p><strong>Error:</strong> \${data.error}</p>\` : ''}
            <p><strong>Check Time:</strong> \${new Date(data.timestamp).toLocaleString()}</p>
          </div>
        \`;
      }
      resultDiv.classList.add('show');
    }

    async function checkAndDisplayDomain(domain, resultDiv) {
      let portRemote = 443;
      let cleanDomain = domain;
      
      if (domain.includes('.tp')) {
        const portMatch = domain.match(/\\.tp(\\d+)\\./);
        if (portMatch) portRemote = parseInt(portMatch[1]);
        cleanDomain = domain.split('.tp')[0];
      } else if (domain.includes('[') && domain.includes(']:')) {
        portRemote = parseInt(domain.split(']:')[1]) || 443;
        cleanDomain = domain.split(']:')[0] + ']';
      } else if (domain.includes(':') && !domain.startsWith('[')) {
        const parts = domain.split(':');
        if (parts.length === 2) {
          cleanDomain = parts[0];
          const parsedPort = parseInt(parts[1]);
          if (!isNaN(parsedPort)) portRemote = parsedPort;
        }
      }
      
      resultDiv.innerHTML = \`<div class="result-card result-warning"><h3><span class="status-icon-prefix">⟳</span> Resolving Domain...</h3><p>Processing \${createCopyButton(cleanDomain)}...</p></div>\`;
      resultDiv.classList.add('show');

      const resolveResponse = await fetch(\`./resolve?domain=\${encodeURIComponent(cleanDomain)}&token=\${TEMP_TOKEN}\`);
      const resolveData = await resolveResponse.json();
      
      if (!resolveData.success) { 
        resultDiv.innerHTML = \`<div class="result-card result-error"><h3><span class="status-icon-prefix">✖</span> Resolution Failed</h3><p>\${resolveData.error || 'Domain resolution failed for ' + createCopyButton(cleanDomain)}</p></div>\`;
        return;
      }
      const ips = resolveData.ips;
      if (!ips || ips.length === 0) { 
        resultDiv.innerHTML = \`<div class="result-card result-error"><h3><span class="status-icon-prefix">✖</span> No IPs Found</h3><p>No IPs found for \${createCopyButton(cleanDomain)}.</p></div>\`;
        return;
      }
      
      ipCheckResults.clear();
      resultDiv.innerHTML = \`
        <div class="result-card result-warning" id="domain-result-card">
          <h3><span class="status-icon-prefix" id="domain-card-icon">⟳</span> Domain Resolution Results</h3>
          <p><strong>Domain:</strong> \${createCopyButton(cleanDomain)}</p>
          <p><strong>Default Port for Test:</strong> \${portRemote}</p>
          <p><strong>IPs Found:</strong> \${ips.length}</p>
          <div class="ip-grid" id="ip-grid" style="max-height: 200px; overflow-y: auto; margin-top:10px; padding:5px;">
            \${ips.map((ip, index) => \`
              <div class="ip-item" id="ip-item-\${index}">
                <div>\${createCopyButton(ip)} <span id="ip-info-\${index}" style="font-size:0.8em;"></span></div>
                <span class="status-icon" id="status-icon-\${index}">⟳</span>
              </div>
            \`).join('')}
          </div>
        </div>
      \`;
      resultDiv.classList.add('show');
      
      const checkPromises = ips.map((ip, index) => checkDomainIPWithIndex(ip, portRemote, index));
      const ipInfoPromises = ips.map((ip, index) => getIPInfoWithIndex(ip, index));
      
      await Promise.all([...checkPromises, ...ipInfoPromises]);

      const domainResultCardEl = document.getElementById('domain-result-card');
      const domainCardIconEl = document.getElementById('domain-card-icon');
      const resultCardHeader = domainResultCardEl.querySelector('h3');

      const validCount = Array.from(ipCheckResults.values()).filter(r => r.success).length;
      
      domainResultCardEl.classList.remove('result-warning', 'result-success', 'result-error');

      if (validCount === ips.length && ips.length > 0) {
        resultCardHeader.childNodes[1].nodeValue = ' All Domain IPs Valid';
        domainCardIconEl.className = 'status-icon-prefix success';
        domainCardIconEl.textContent = '✔';
        domainResultCardEl.classList.add('result-success');
      } else if (validCount === 0) {
        resultCardHeader.childNodes[1].nodeValue = ' All Domain IPs Invalid';
        domainCardIconEl.className = 'status-icon-prefix error';
        domainCardIconEl.textContent = '✖';
        domainResultCardEl.classList.add('result-error');
      } else {
        resultCardHeader.childNodes[1].nodeValue = \` Some Domain IPs Valid (\${validCount}/\${ips.length})\`;
        domainCardIconEl.className = 'status-icon-prefix warning';
        domainCardIconEl.textContent = '⚠';
        domainResultCardEl.classList.add('result-warning');
      }
    }

    async function checkDomainIPWithIndex(ip, port, index) {
      const statusIcon = document.getElementById(\`status-icon-\${index}\`);
      try {
        const ipToTest = ip.includes(':') || ip.includes(']:') ? ip : \`\${ip}:\${port}\`;
        const result = await fetchSingleIPCheck(ipToTest);
        ipCheckResults.set(ipToTest, result);
        
        if (statusIcon) {
          statusIcon.textContent = result.success ? '✔' : '✖';
          statusIcon.style.color = result.success ? 'var(--success)' : 'var(--error)';
        }
      } catch (error) {
        if (statusIcon) {
          statusIcon.textContent = '⚠';
          statusIcon.style.color = 'var(--warning)';
        }
        ipCheckResults.set(ip, { success: false, error: error.message });
      }
    }
    
    async function getIPInfoWithIndex(ip, index) {
      try {
        const ipInfo = await getIPInfo(ip.split(':')[0]);
        const infoElement = document.getElementById(\`ip-info-\${index}\`);
        if (infoElement) infoElement.innerHTML = formatIPInfo(ipInfo, true);
      } catch (error) { }
    }

    async function getIPInfo(ip) {
      try {
        const cleanIP = ip.replace(/[\\[\\]]/g, '');
        const response = await fetch(\`./ip-info?ip=\${encodeURIComponent(cleanIP)}&token=\${TEMP_TOKEN}\`);
        return await response.json();
      } catch (error) { return null; }
    }

    function formatIPInfo(ipInfo, isShort = false) {
      if (!ipInfo || ipInfo.status !== 'success') { return ''; }
      const country = ipInfo.country || 'N/A';
      const as = ipInfo.as || 'N/A';
      const colorStyle = \`color: var(--text-secondary);\`;
      if(isShort) return \`<span style="\${colorStyle}">(\${country} - \${as.substring(0,15)}...)</span>\`;
      return \`<span style="font-size:0.85em; \${colorStyle}">(\${country} - \${as})</span>\`;
    }
  </script>
</body>
</html>
`;
  return new Response(html, {
    headers: { 'content-type': 'text/html;charset=UTF-8' },
  });
}