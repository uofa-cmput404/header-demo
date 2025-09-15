const http = require("http"); // node!
const assert = require('node:assert').strict;

const nunjucks = require("nunjucks");
const multipart = require("parse-multipart-data");
const BufferHex = require("buffer-hex").BufferHex;

const host = '';
const port = 9000;

const split1 = function (str, sep) {
    let at = str.indexOf(sep);
    if (at >= 0) {
        let first = str.slice(0, at);
        let rest = str.slice(at + 1);
        return [first, rest];
    } else {
        return [str, ""];
    }
}

const noCaseCompare = function (a, b) {
    assert.equal(typeof a, 'string');
    assert.equal(typeof b, 'string');
    return (
        a.localeCompare(b, undefined, {
            "sensitivity": "base",
        })
        === 0
    );
}

const breakCircularReferences = () => {
    const references = [];
    const reference_keys = [];
        return (key, value) => {
        let found = false;
        if (
            value === null
            || value === undefined
            || !Object.keys(value).length
        ) {
            return value;
        }
        let reference_key;
        for (index in references) {
            reference = references[index];
            reference_key = reference_keys[index];
            if (Object.is(value, reference)) {
                found = true;
            }
        }
        if (found) {
            return ''+value+' '+reference_key;
        } else if (typeof value === "object") {
            references.push(value);
            reference_keys.push(key);
            return value;
        } else {
            return value;
        }
    };
};

const fix6 = function (addr) {
    addr = ''+addr;
    if (addr.includes('.')) {
        return addr.replace('::ffff:', '');
    } else if (addr.includes(':')) {
        return '[' + addr + ']';
    } else {
        return addr;
    }
}

const params2Aarray = function(params) {
    const r = [];
    for (const [name, value] of params) {
        r.push({
            name: name,
            value: value,
        })
    }
    return r;
}

const requestListener = function (req, res) {
    let read = 0;
    let chunks = [];
    let tooBig = false;
    req.on('readable', () => {
        let chunk;
        while (null != (chunk = req.read(128))) {
            if (!tooBig) {
                chunks.push(chunk);
                read += chunk.length;
            }
            if (read > 1024) {
                tooBig = true;
            }
        }
    });
    req.on('end', () => {
        const context = {
            read: read,
            body: chunks.join(''),
        };
        chunks = Buffer.concat(chunks);
        context.request_string = JSON.stringify(req, breakCircularReferences(), '  ');
        try {
            var url = new URL(req.url, `http://${req.headers.host}`);
        } catch (error) {
            res.setHeader('Content-Type', 'text/plain; charset=UTF-8');
            res.writeHead(400, "Bad Request");
            res.end("Invalid host header: " + req.headers.host + "\n" + error.message);
            return;
        }
        context.url = '' + url;
        res.setHeader('Content-Type', 'text/html; charset=UTF-8');
        // res.setHeader('X-Frame-Options', 'DENY');
        // res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Content-Security-Policy', "default-src 'self';");
        res.setHeader('Vary', 'Origin');
        res.setHeader('Cache-Control', 'no-cache');
        // res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
        // res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
        // res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=(), interest-cohort=()');
        if (tooBig) {
            res.writeHead(413, "Request Entity Too Large");
        } else if (url.pathname.includes("/basic") && !req.headers['authorization']) {
            res.writeHead(401, "Unauthorized", {
                'WWW-Authenticate': 'Basic realm="Enter any username and password"',
            });
        } else if (url.pathname.endsWith("/redirect/301/")) {
            res.writeHead(301, "Moved Permanently", {
                'Location': '../../',
            });
        } else {
            res.writeHead(200, "OK", {
            });
        }
        context.statusCode = res.statusCode;
        context.statusMessage = res.statusMessage;
        context.headers_string = JSON.stringify(req.headers, undefined, '  ');
        context.search_params = JSON.stringify(Object.fromEntries(url.searchParams), undefined, '  ');
        context.ipv = req.socket.remoteFamily;
        context.from_host = fix6(req.socket.remoteAddress);
        context.from_port = req.socket.remotePort;
        context.to_host = fix6(req.socket.localAddress);
        context.to_port = req.socket.localPort;
        context.version = req.httpVersion;
        context.method = req.method;
        context.path = req.url;
        context.protocol = url.protocol;
        context.username = url.username;
        context.password = url.password;
        context.host = url.host;
        context.hostname = url.hostname;
        context.port = url.port;
        context.pathname = url.pathname;
        context.search = url.search;
        context.hash = url.hash;
        context.origin = url.origin;
        if (req.headers['authorization']) {
            let auth = req.headers['authorization'];
            let [auth_kind, auth_value] = split1(req.headers.authorization, " ");
            context.auth_kind = auth_kind;
            context.auth_value = auth_value;
            if (noCaseCompare(auth_kind, "Basic")) {
                context.basic = Buffer.from(auth_value, 'base64').toString();
                [context.user, context.password] = split1(context.basic, ":");
            }
        }
        if (req.headers['content-type']) {
            const [contentType, ctArg] = split1(req.headers['content-type'], ";");
            context.contentType = contentType;
            context.ctArg = ctArg;
            if (noCaseCompare(contentType, "application/x-www-form-urlencoded")) {
                try {
                    context.postData = params2Aarray(new URLSearchParams(context.body));
                } catch (err) {
                    context.postError = '' + err;
                }
            } else if (noCaseCompare(contentType, "multipart/form-data")) {
                const [ctArgKey, ctArgVal] = split1(ctArg, "=");
                context.boundary = false;
                if (ctArgKey.includes("boundary")) {
                    context.boundary = ctArgVal;
                }
                if (context.boundary) {
                    try {
                        const parts = multipart.parse(chunks, context.boundary);
                        context.parts = parts.length;
                        for (part of parts) {
                            if (Buffer.isBuffer(part.data)) {
                                part.data = BufferHex.dump(part.data);
                            }
                        }
                        context.postData = parts;
                    } catch (err) {
                        context.postError = '' + err;
                    }
                } else {
                    context.postError = "Couldn't find the boundary? " + ctArgKey + "..." + ctArgVal
                }
            }
        }
        everything = structuredClone(context);
        everything.request = JSON.parse(JSON.stringify(req, breakCircularReferences()));
        delete everything.request_string;
        everything.headers = JSON.parse(everything.headers_string);
        delete everything.headers_string;
        everything.search_params = JSON.parse(everything.search_params);
        everything = JSON.stringify(everything, undefined, 2);
        context.everything = everything;
        context.everything_comment = everything.replaceAll('--', '\\u002d\\u002d');
        if (url.pathname.includes("/form")) {
            res.end(nunjucks.render("form.njk", context));
        } else {
            res.end(nunjucks.render("index.njk", context));
        }
    });
};

const main = function () {
    nunjucks.configure({
        autoescape: true,
        noCache: true,
    });
    const server = http.createServer(requestListener);
    server.listen(port, host, () => {
        console.log(`Server is running on http://${host}:${port}`);
    });
}

main();
