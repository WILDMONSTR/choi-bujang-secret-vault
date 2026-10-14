async function readJson(response) {
  const data = await response.json().catch(() => null);
  if (!response.ok) throw new Error(data?.error || ('HTTP_' + response.status));
  return data;
}

function validLocalPath(path) {
  return typeof path === 'string' && path.startsWith('/') && !path.startsWith('//')
    && !path.includes('#') && !path.includes('\\r') && !path.includes('\\n');
}

export async function deviceRequest(path, method = 'GET', payload) {
  if (!validLocalPath(path)) throw new Error('INVALID_REQUEST_PATH');
  const verb = String(method).toUpperCase();
  const options = {
    method: verb,
    cache: 'no-store',
    credentials: 'same-origin',
    headers: { Accept: 'application/json' }
  };
  if (payload !== undefined) {
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(payload);
  }
  return readJson(await fetch(path, options));
}

export async function getDeviceStatus() {
  return deviceRequest('/api/devices/status', 'GET');
}

export async function registerCurrentDevice() {
  const response = await fetch('/api/devices/register', {
    method: 'POST',
    cache: 'no-store',
    credentials: 'same-origin',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({
      label: (navigator.userAgentData?.platform || navigator.platform || '이 브라우저').slice(0, 80)
    })
  });
  return readJson(response);
}

export async function approveCurrentDevice(email, password) {
  const response = await fetch('/api/devices/approve-self', {
    method: 'POST',
    cache: 'no-store',
    credentials: 'same-origin',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  return readJson(response);
}
