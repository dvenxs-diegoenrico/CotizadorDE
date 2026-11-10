// Protege todo el sitio con contraseña. Solo se guardan hashes SHA-256, nunca la contraseña en texto.
export const config = { matcher: ['/((?!login\\.html|logo\\.svg|favicon\\.ico).*)'] };

const PW_HASH = '6fa2a1d2a2bef4858fcff3f9760b41d922057063821b561839c0e46e65641cc9';
const TOKEN_HASH = '3075a6fababea34f43fbe9795e662ce5c76c8dbaee3d3b752cd6406b5a63c357';
const COOKIE = 'de_session';
const MAX_AGE = 60 * 60 * 24 * 30; // 30 días

async function sha256(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function getCookie(req, name) {
  const raw = req.headers.get('cookie') || '';
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return null;
}

const redirect = (url, headers = {}) => new Response(null, { status: 303, headers: { Location: url, 'Cache-Control': 'no-store', ...headers } });

export default async function middleware(req) {
  const url = new URL(req.url);

  if (url.pathname === '/auth' && req.method === 'POST') {
    const form = await req.formData();
    const pw = String(form.get('password') || '');
    if ((await sha256(pw)) === PW_HASH) {
      const token = await sha256('de-session-v1:' + pw);
      return redirect('/', { 'Set-Cookie': `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${MAX_AGE}` });
    }
    return redirect('/login.html?error=1');
  }

  if (url.pathname === '/logout') {
    return redirect('/login.html', { 'Set-Cookie': `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0` });
  }

  const token = getCookie(req, COOKIE);
  if (token && (await sha256(token)) === TOKEN_HASH) return; // acceso permitido

  return redirect('/login.html');
}
