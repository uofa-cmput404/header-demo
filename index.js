const http = require("http"); // node!
const assert = require('node:assert').strict;

const html_entities = require('html-entities');
const encode = html_entities.encode;
const nunjucks = require("nunjucks");

const host = 'localhost';
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

const breakCircularReferences = function (key, value) {
    let found = false;
    if (
        value === null
        || value === undefined
        || !Object.keys(value).length
    ) {
        return value;
    }
    for (reference of references) {
        if (Object.is(value, reference)) {
            found = true;
        }
    }
    if (found) {
        return "...";
    } else {
        references.push(value);
        return value;
    }
}

const fix6 = function (addr) {
    if (addr.includes(':')) {
        return '[' + addr + ']';
    } else {
        return addr;
    }
}

const requestListener = function (req, res) {
    const context = {};
    const references = [];
    const breakCircularReferences = function (key, value) {
        let found = false;
        if (
            value === null
            || value === undefined
            || !Object.keys(value).length
        ) {
            return value;
        }
        for (reference of references) {
            if (Object.is(value, reference)) {
                found = true;
            }
        }
        if (found) {
            return "...";
        } else {
            references.push(value);
            return value;
        }
    }
    context.request_string = JSON.stringify(req, breakCircularReferences, '  ');
    const url = new URL(req.url, `http://${req.headers.host}`);
    context.url = '' + url;
    res.setHeader('Content-Type', 'text/html');
    if (url.pathname.includes("/basic") && !req.headers['authorization']) {
        res.writeHead(401, "Unauthorized", {
            'WWW-Authenticate': 'Basic realm="Enter any username and password"',
        });
    } else {
        res.writeHead(200, "OK", {
        });
    }
    context.headers_string = JSON.stringify(req.headers, undefined, '  ');
    context.search_params = JSON.stringify(Object.fromEntries(url.searchParams), undefined, '  ');
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
    res.end(
        nunjucks.render("index.njk", context)
    );
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
