/* ══════════════════════════════════════════════════════════════════════════
   OneStop DriveIn — sign-in for the database
   ══════════════════════════════════════════════════════════════════════════
   One shared file, used by all five pages. Every page loads it like this,
   in the <head>, BEFORE anything else:

     <script>window.OS_AUTH = { role:'owner', title:'Cash & accounts' };</script>
     <script src="os-auth.js"></script>

   role:'owner'  → asks for the password, then opens the whole database
   role:'staff'  → signs in quietly, can only touch the duty tracker

   What it does: every call the apps make to the database gets the signed-in
   token attached. Without a valid token the database now refuses to answer,
   so the data is no longer open to whoever finds the address.
   ══════════════════════════════════════════════════════════════════════════ */
(function(){
'use strict';

/* ─────────── settings ─────────── */
var API_KEY     = 'AIzaSyAHscKi2FwP-aS0CxhGNym3_BH5k5diqjc';
var OWNER_EMAIL = 'owner@onestopdrivein.com';   // the one account that sees everything
var DB_HOST     = 'attendance-and-salary-tr-20681-default-rtdb.asia-southeast1.firebasedatabase.app';
var HOLD_HOURS  = 12;        // how long a phone stays open before the password is asked again

var CFG   = window.OS_AUTH || {};
var ROLE  = CFG.role === 'staff' ? 'staff' : 'owner';
var GATE  = CFG.gate !== false && ROLE === 'owner';   // the hub sets gate:false
var TITLE = CFG.title || document.title || '';
var HOME  = CFG.home  || 'index.html';

var K = {
  refresh: 'os-' + ROLE + '-refresh',
  until:   'os-owner-until',
  tok:     'os-' + ROLE + '-tok',       // the live token, so a new page does not
  tokexp:  'os-' + ROLE + '-tokexp'     // have to fetch a fresh one every time
};
function ls(k){ try{ return localStorage.getItem(k); }catch(e){ return null; } }
function lsSet(k,v){ try{ localStorage.setItem(k,v); }catch(e){} }
function lsDel(k){ try{ localStorage.removeItem(k); }catch(e){} }

/* ─────────── token handling ─────────── */
var idToken = null, expiresAt = 0, pending = null;

/* A Firebase token is good for an hour. Every app used to throw its own away on
   load and ask for a new one before it could read anything, which is a whole
   round trip added to opening any screen. Keeping it on the phone removes that. */
(function reuseToken(){
  var t = ls(K.tok), x = +ls(K.tokexp) || 0;
  if(t && Date.now() < x){ idToken = t; expiresAt = x; }
})();
var waiters = [];                       // fetches parked until sign-in finishes

function held(){                        // owner sessions time out; staff never do
  if(ROLE === 'staff') return true;
  return Date.now() < (+ls(K.until) || 0);
}
function holdOpen(){ lsSet(K.until, String(Date.now() + HOLD_HOURS*3600000)); }

function post(url, body, form){
  return fetch(url, {
    method:'POST',
    headers:{'Content-Type': form ? 'application/x-www-form-urlencoded' : 'application/json'},
    body: form ? body : JSON.stringify(body)
  }).then(function(r){
    return r.json().then(function(j){
      if(!r.ok) throw new Error((j && j.error && j.error.message) || 'auth failed');
      return j;
    });
  });
}
function keep(tok, refresh, secs){
  idToken   = tok;
  expiresAt = Date.now() + (Number(secs||3600) - 120) * 1000;
  lsSet(K.tok, tok); lsSet(K.tokexp, String(expiresAt));
  if(refresh) lsSet(K.refresh, refresh);
  var q = waiters; waiters = [];
  q.forEach(function(w){ w.ok(tok); });
  return tok;
}
function fail(err){
  var q = waiters; waiters = [];
  q.forEach(function(w){ w.no(err); });
  throw err;
}

function signInPassword(pw){
  return post('https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key='+API_KEY,
              {email:OWNER_EMAIL, password:pw, returnSecureToken:true})
    .then(function(j){ holdOpen(); return keep(j.idToken, j.refreshToken, j.expiresIn); });
}
function signInAnonymous(){
  return post('https://identitytoolkit.googleapis.com/v1/accounts:signUp?key='+API_KEY,
              {returnSecureToken:true})
    .then(function(j){ return keep(j.idToken, j.refreshToken, j.expiresIn); });
}
function refreshToken(){
  var rt = ls(K.refresh);
  if(!rt) return Promise.reject(new Error('no session'));
  return post('https://securetoken.googleapis.com/v1/token?key='+API_KEY,
              'grant_type=refresh_token&refresh_token='+encodeURIComponent(rt), true)
    .then(function(j){ return keep(j.id_token, j.refresh_token, j.expires_in); })
    .catch(function(e){ lsDel(K.refresh); throw e; });
}

/* Hands back a usable token, signing in if it has to. */
function token(){
  if(idToken && Date.now() < expiresAt) return Promise.resolve(idToken);
  if(pending) return pending;

  if(ROLE === 'staff'){
    pending = (ls(K.refresh) ? refreshToken().catch(signInAnonymous) : signInAnonymous())
      .then(function(t){ pending = null; return t; })
      .catch(function(e){ pending = null; throw e; });
    return pending;
  }
  if(!held() || !ls(K.refresh)){
    /* Nothing to sign in with. Park the call, but put the password screen up as
       well — without it the app waits on a token that is never coming and simply
       looks frozen. */
    if(GATE) showGate();
    return new Promise(function(ok,no){ waiters.push({ok:ok,no:no}); });
  }
  pending = refreshToken()
    .then(function(t){ pending = null; return t; })
    .catch(function(e){ pending = null; if(GATE) showGate(); throw e; });
  return pending;
}

/* ─────────── every database call gets the token attached ─────────── */
var rawFetch = window.fetch.bind(window);
window.fetch = function(input, init){
  var url = typeof input === 'string' ? input : (input && input.url) || '';
  if(url.indexOf(DB_HOST) === -1) return rawFetch(input, init);

  var call = function(tok, retry){
    var u = url + (url.indexOf('?') > -1 ? '&' : '?') + 'auth=' + encodeURIComponent(tok);
    return rawFetch(u, init).then(function(r){
      if((r.status === 401 || r.status === 403) && !retry){
        idToken = null; expiresAt = 0;         // token went stale — get a fresh one and retry once
        lsDel(K.tok); lsDel(K.tokexp);
        return token().then(function(t2){ return call(t2, true); });
      }
      return r;
    });
  };
  if(ROLE === 'owner' && !GATE && !held()) return Promise.reject(new Error('locked'));
  return token().then(function(t){ return call(t, false); });
};

/* ─────────── the password screen ─────────── */
var gateEl = null, typed = '', busy = false;

function paintStyle(){
  if(document.getElementById('osAuthCss')) return;
  var s = document.createElement('style');
  s.id = 'osAuthCss';
  s.textContent =
  'html.os-locked body > *:not(#osGate){display:none !important}'+
  /* The strip is pinned to the top of the screen. It used to scroll away with the
     page, so on any long screen — the stock list, the cash tape — Home was simply
     not there any more, which reads as a button that does not work. */
  '#osHomeBar{position:sticky;top:0;z-index:2147482000;'+
    'display:flex;align-items:center;gap:10px;padding:calc(5px + env(safe-area-inset-top)) 12px 5px;'+
    'background:#0E2230;color:#fff;font:500 13px/1 system-ui,-apple-system,"Segoe UI",sans-serif;'+
    'box-shadow:0 1px 0 rgba(201,162,39,.35)}'+
  /* An app header that PINS ITSELF to the top has to start below the strip,
     otherwise the two land on the same line and cover each other. The class is
     put on by hand after checking, because on a header that merely sits in the
     flow (position:relative) a top offset shoves it down over the page instead. */
  'html.os-pinned-head body > header{top:var(--os-bar-h,0px)}'+
  '.dayhd{top:var(--os-bar-h,0px)}'+
  '#osHomeBar a{display:inline-flex;align-items:center;gap:6px;color:#fff;text-decoration:none;'+
    'background:rgba(255,255,255,.10);border:1px solid rgba(201,162,39,.45);border-radius:20px;padding:6px 13px}'+
  '#osHomeBar a:active{background:rgba(255,255,255,.2)}'+
  '#osHomeBar .os-t{flex:1;min-width:0;color:#8FA6B2;font-size:10px;letter-spacing:.2em;text-transform:uppercase;'+
    'overflow:hidden;text-overflow:ellipsis;white-space:nowrap;text-align:right}'+
  '#osHomeBar button{background:none;border:0;color:#8FA6B2;font:inherit;font-size:11px;padding:7px 4px;cursor:pointer}'+
  '#osGate{position:fixed;inset:0;z-index:2147483000;background:#0E2230;color:#fff;overflow:auto;'+
    'display:flex;align-items:center;justify-content:center;padding:24px 20px calc(24px + env(safe-area-inset-bottom));'+
    'font-family:system-ui,-apple-system,"Segoe UI",sans-serif}'+
  '#osGate .os-box{width:100%;max-width:300px;text-align:center}'+
  '#osGate .os-mark{display:inline-block;padding:9px 20px 8px;border-radius:14px;margin-bottom:18px;'+
    'background:linear-gradient(180deg,rgba(201,162,39,.20),rgba(201,162,39,.07));'+
    'border:1px solid rgba(201,162,39,.55);font-weight:800;font-size:17px;letter-spacing:.02em;text-transform:uppercase}'+
  '#osGate .os-mark i{font-style:normal;color:#C9A227}'+
  '#osGate h1{font-size:17px;font-weight:600;margin:0 0 4px}'+
  '#osGate p{font-size:12.5px;color:#8FA6B2;margin:0 0 20px}'+
  '#osGate .os-dots{display:flex;justify-content:center;gap:9px;flex-wrap:wrap;min-height:14px;margin-bottom:8px}'+
  '#osGate .os-dots i{width:10px;height:10px;border-radius:50%;background:rgba(255,255,255,.16);transition:.15s}'+
  '#osGate .os-dots i.on{background:#C9A227;transform:scale(1.12)}'+
  '#osGate .os-msg{font-size:12px;color:#E2614C;height:32px;margin-bottom:8px;line-height:1.35}'+
  '#osGate .os-pad{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}'+
  '#osGate .os-pad button{height:58px;border-radius:14px;border:1px solid rgba(255,255,255,.14);'+
    'touch-action:manipulation;user-select:none;-webkit-user-select:none;'+
    'background:rgba(255,255,255,.06);color:#fff;font-size:22px;font-weight:500;cursor:pointer;font-variant-numeric:tabular-nums}'+
  '#osGate .os-pad button:active{background:rgba(201,162,39,.28)}'+
  '#osGate .os-pad button.os-act{font-size:14px;color:#8FA6B2}'+
  '#osGate .os-pad button.os-go{background:#C9A227;border-color:#C9A227;color:#231A00;font-weight:700;font-size:16px}'+
  '#osGate .os-pad button[disabled]{opacity:.45}'+
  '#osGate .os-back{margin-top:18px;background:none;border:0;color:#8FA6B2;font-size:13px;'+
    'text-decoration:underline;cursor:pointer;font-family:inherit}'+
  '#osGate .os-shake{animation:osShake .3s}'+
  '@keyframes osShake{0%,100%{transform:translateX(0)}25%{transform:translateX(-7px)}75%{transform:translateX(7px)}}'+
  '@media(prefers-reduced-motion:reduce){#osGate .os-shake{animation:none}}';
  (document.head || document.documentElement).appendChild(s);
}

function dots(){
  var box = gateEl.querySelector('.os-dots'), h = '', n = Math.max(8, typed.length);
  for(var i=0;i<n;i++) h += '<i class="'+(i<typed.length?'on':'')+'"></i>';
  box.innerHTML = h;
}
function say(m){ gateEl.querySelector('.os-msg').textContent = m || ''; }
function shake(){
  var b = gateEl.querySelector('.os-box');
  b.classList.add('os-shake');
  setTimeout(function(){ b.classList.remove('os-shake'); }, 320);
}
function friendly(msg){
  if(/INVALID_LOGIN|INVALID_PASSWORD|EMAIL_NOT_FOUND|INVALID_CREDENTIAL/.test(msg)) return 'Wrong password. Try again.';
  if(/TOO_MANY_ATTEMPTS/.test(msg)) return 'Too many tries. Wait a few minutes, then try again.';
  if(/USER_DISABLED/.test(msg)) return 'This account has been turned off in Firebase.';
  if(/NETWORK|Failed to fetch|network/i.test(msg)) return 'No connection. Check the internet and try again.';
  return 'Could not sign in. ' + msg;
}
function submit(){
  if(busy || !typed) return;
  if(typed.length < 6){ say('The password is six digits or more.'); shake(); typed=''; dots(); return; }
  busy = true; say('Signing in…');
  gateEl.querySelectorAll('.os-pad button').forEach(function(b){ b.disabled = true; });
  signInPassword(typed).then(function(){
    if(GATE){ location.reload(); return; }
    hideGate();
    if(typeof CFG.onOpen === 'function') CFG.onOpen();
  }).catch(function(e){
    busy = false; typed = ''; dots();
    gateEl.querySelectorAll('.os-pad button').forEach(function(b){ b.disabled = false; });
    say(friendly(e.message || '')); shake();
  });
}
function buildGate(){
  paintStyle();
  gateEl = document.createElement('div');
  gateEl.id = 'osGate';
  gateEl.innerHTML =
    '<div class="os-box">'+
      '<div class="os-mark">OneStop <i>DriveIn</i></div>'+
      '<h1>'+String(TITLE).replace(/[<>]/g,'')+'</h1>'+
      '<p>Enter the password to open this.</p>'+
      '<div class="os-dots"></div>'+
      '<div class="os-msg"></div>'+
      '<div class="os-pad">'+
        '<button type="button" data-k="1">1</button><button type="button" data-k="2">2</button><button type="button" data-k="3">3</button>'+
        '<button type="button" data-k="4">4</button><button type="button" data-k="5">5</button><button type="button" data-k="6">6</button>'+
        '<button type="button" data-k="7">7</button><button type="button" data-k="8">8</button><button type="button" data-k="9">9</button>'+
        '<button type="button" class="os-act" data-k="del">Delete</button>'+
        '<button type="button" data-k="0">0</button>'+
        '<button type="button" class="os-go" data-k="go">Open</button>'+
      '</div>'+
      '<button type="button" class="os-back">'+(GATE ? 'Back to Home' : 'Cancel')+'</button>'+
    '</div>';
  gateEl.querySelectorAll('.os-pad button').forEach(function(b){
    b.onclick = function(){
      if(busy) return;
      var k = b.dataset.k;
      say('');
      if(k === 'del')      typed = typed.slice(0,-1);
      else if(k === 'go')  return submit();
      else if(typed.length < 24) typed += k;
      dots();
    };
  });
  gateEl.querySelector('.os-back').onclick = function(){
    if(GATE) location.href = HOME; else hideGate();
  };
  document.addEventListener('keydown', function(e){
    if(!gateEl || !gateEl.isConnected || busy) return;
    if(/^[0-9]$/.test(e.key) && typed.length < 24){ typed += e.key; say(''); dots(); }
    else if(e.key === 'Backspace'){ typed = typed.slice(0,-1); dots(); }
    else if(e.key === 'Enter'){ submit(); }
  });
  dots();
}
function showGate(){
  if(!gateEl) buildGate();
  if(!gateEl.isConnected) (document.body || document.documentElement).appendChild(gateEl);
  document.documentElement.classList.add('os-locked');
  typed = ''; busy = false; say(''); dots();
}
function hideGate(){
  document.documentElement.classList.remove('os-locked');
  if(gateEl && gateEl.isConnected) gateEl.remove();
}

/* ─────────── the Home strip at the top of each app ─────────── */
function homeBar(){
  if(!document.body || document.getElementById('osHomeBar')) return;
  paintStyle();
  var bar = document.createElement('div');
  bar.id = 'osHomeBar';
  bar.innerHTML = '<a href="'+HOME+'">&#8962; '+(ROLE === 'staff' ? 'హోమ్ · Home' : 'Home')+'</a>'+
                  '<span class="os-t">'+String(TITLE).replace(/[<>]/g,'')+'</span>'+
                  (ROLE === 'owner' ? '<button type="button" id="osLockNow">Lock</button>' : '');
  document.body.insertBefore(bar, document.body.firstChild);
  var lock = document.getElementById('osLockNow');
  if(lock) lock.onclick = function(){ OSAuth.signOut(); location.reload(); };
  /* A page that pins its own header needs to know how tall this strip is. The
     figure is re-taken on rotation, because the safe area changes with it. */
  var measure = function(){
    var h = bar.offsetHeight || 0;
    document.documentElement.style.setProperty('--os-bar-h', h + 'px');
    var hd = document.querySelector('body > header');
    var pos = hd ? getComputedStyle(hd).position : '';
    document.documentElement.classList.toggle('os-pinned-head',
      pos === 'sticky' || pos === 'fixed');
  };
  measure();
  setTimeout(measure, 250);                       // again once the fonts have landed
  window.addEventListener('resize', measure);
  window.addEventListener('orientationchange', function(){ setTimeout(measure, 250); });
  /* Tapping Home while a keyboard is open can leave the page mid-scroll on iOS,
     so the link is followed by hand once the field has let go. */
  var a = bar.querySelector('a');
  a.addEventListener('click', function(ev){
    if(ev.metaKey || ev.ctrlKey || ev.shiftKey) return;   // let "open in new tab" work
    ev.preventDefault();
    if(document.activeElement && document.activeElement.blur) document.activeElement.blur();
    location.href = HOME;
  });
}

/* ─────────── what the pages can call ─────────── */
window.OSAuth = {
  role: ROLE,
  email: OWNER_EMAIL,
  isOpen: function(){ return held() && !!ls(K.refresh); },
  openUntil: function(){ return +ls(K.until) || 0; },
  signIn: signInPassword,
  ask: showGate,
  token: token,
  signOut: function(){ lsDel(K.refresh); lsDel(K.until); lsDel(K.tok); lsDel(K.tokexp);
                       idToken = null; expiresAt = 0; },
  /* changes the password on the Firebase account itself */
  changePassword: function(next){
    return token().then(function(t){
      return post('https://identitytoolkit.googleapis.com/v1/accounts:update?key='+API_KEY,
                  {idToken:t, password:next, returnSecureToken:true});
    }).then(function(j){ holdOpen(); return keep(j.idToken, j.refreshToken, j.expiresIn); });
  }
};

/* ─────────── start ─────────── */
if(GATE && !OSAuth.isOpen()){
  paintStyle();
  document.documentElement.classList.add('os-locked');   // hides the app before it ever paints
}
if(document.readyState === 'loading'){
  document.addEventListener('DOMContentLoaded', start);
} else if(document.body){ start(); }
else { document.addEventListener('DOMContentLoaded', start); }

function start(){
  if(CFG.homeBar !== false) homeBar();
  /* get the token moving in parallel with the page drawing itself */
  if(!idToken && held() && ls(K.refresh)) token().catch(function(){});
  if(GATE && !OSAuth.isOpen()) showGate();
  else if(ROLE === 'owner' && GATE) token().catch(function(){ showGate(); });
  else if(ROLE === 'staff') token().catch(function(){});
}
})();
