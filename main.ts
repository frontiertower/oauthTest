//////// deno run --allow-net --allow-read --allow-write --unstable-kv --watch ./main.ts 3141

const start = Date.now();
function log(msg: string) {
    const prefix = ((Date.now() - start) / 1000).toFixed(3) + "> ";
    console.log(prefix + msg);
}

const CONFIG = {
    port: parseInt(Deno.args.at(0) || "3141"),

    /*
        {
            "CLIENT_ID": "O..................V",
            "SECRET": "4......................................0",
            "REDIRECT_URI": "https://..../api/oauth"
        }
    */
    secretsJson: '.secrets.json',

    // OAuth server GET endpoint for step 1
////oauthAuthorizeUrl: "https://api.berlinhouse.com/o/authorize/",
    oauthAuthorizeUrl: "https://github.com/login/oauth/authorize?scope=read:user&response_type=code",
    // OAuth server POST endpoint for step 2
////oauthTokenUrl: "https://api.berlinhouse.com/o/token/",
    oauthTokenUrl: "https://github.com/login/oauth/access_token",

    // Url of the app server that recieves the callback from Oauth server is in SECRETS. It should match this path.
    callbackPath: "/api/oauth",

    kvPath: ".kv",
}

const SECRETS = JSON.parse(await Deno.readTextFile(CONFIG.secretsJson));
if (new URL(SECRETS.REDIRECT_URI).pathname !== CONFIG.callbackPath) {
    throw Error(`.secrets.json redirect_uri's path "${SECRETS.REDIRECT_URI}" must match callbackPath "${CONFIG.callbackPath}"`);
}

// OAuth call to revoke token from step 2 above
const oauthTokenRevokeUrl = `https://api.github.com/applications/${SECRETS.client_id}/token`;

log(`Booting @ ${new Date()}`);

const kv = await Deno.openKv(CONFIG.kvPath); // Deno key-value store.
async function mainHandler(req: Request, _connInfo: Deno.ServeHandlerInfo): Promise<Response> {
    const url = new URL(req.url);
    const pathname = url.pathname;
    log(`Request for ${pathname}`);

    //////// Step 0: Identify the browser with a cookie.
    const cookies = req.headers.get("Cookie");
    const idCookie = cookies?.split(";").find((c) => c.trim().startsWith("id="));
    let cookie = idCookie ? idCookie.split("=")[1] : null;

    const responseHeaders = new Headers({ "content-type": "text/html; charset=utf-8" });

    if (!cookie) {
        // Generate a new ID using cryptographic RNG
        const idArray = new Uint8Array(16);
        crypto.getRandomValues(idArray);
        cookie = Array.from(idArray).map((b) => b.toString(16).padStart(2, '0')).join('');
        responseHeaders.append("Set-Cookie", `id=${cookie}; HttpOnly; Path=/`);
        log(`  Generated new cookie: ${cookie}`);
    } else {
        log(`  User supplied cookie: ${cookie}`);
    }

    //////// Step 1:  Check if that cookie has an OAuth Token in KV
    const authRecord = await kv.get(['cookies', cookie, 'token']);
    const isAuthenticated = authRecord.value ? true : false;
    if (authRecord.value) {
        log(`  Cookie ${cookie} has OAuth token`);
    } else {
        log(`  Cookie ${cookie} does not have OAuth token`);
    }

    //////// Define HTTP endpoints for "/" and "/api/oauth"
    // Simple HTML to avoid frontend frameworks
    const PREFIX = `<!DOCTYPE html>
<html>
    <head>
        <title>FT OAuth Demo</title>
    </head>
    <body>
`;
      const SUFFIX = `
    </body>
</html>
`;

    // The only real HTML page is the root page.
    if (pathname === "/") {
        if (isAuthenticated) {
            //////// Step 4: Get some useful private data from the API.
            //const response = await fetch('https://api.berlinhouse.io/auth/users/me/', {
            const response = await fetch('https://api.github.com/user', {
                headers: {
                    "Accept": "application/json",
                    "Authorization": `Bearer ${authRecord.value}`,
                }
            });
            const json = await response.json();

            return new Response(`${PREFIX}
                    <h1>OAuth User Page</h1>
                    <p>Cookie: ${cookie}</p>
                    <p><b>API call: ${response.status === 200 ? "SUCCESS" : "FAILED"}</b></p>
                    <pre>${JSON.stringify(json, null, 2)}</pre>
                    <a href="/api/logout">Log out</a>
                    ${SUFFIX}`,
                { headers: responseHeaders },
            );
        } else {
            //////// Step 2:  Create a login page
            const CSRF = crypto.randomUUID();  // https://en.wikipedia.org/wiki/Cross-site_request_forgery
            await kv.set(['cookies', cookie, 'CSRF'], CSRF);
            log(`  Saved CSRF for ${cookie}: ${CSRF}`);
            const oAuthLoginLink =
                `${CONFIG.oauthAuthorizeUrl}` +              // Oauth server's auth endpoint
                `&client_id=${SECRETS.CLIENT_ID}` +          // Hardcoded OAuth server's login information for this app
                `&redirect_uri=${SECRETS.REDIRECT_URI}` +    // Where the browser goes once the OAuth succeeds
                `&state=${CSRF}`;

            return new Response(`${PREFIX}
                    <h1>OAuth Login Page</h1>
                    <p>Cookie ${cookie} not authenticated.</p>
                    <a href="${oAuthLoginLink}">Login with GitHub</a>
                ${SUFFIX}`,
                { headers: responseHeaders },
            );
        }
    } else if (pathname === CONFIG.callbackPath) {
        const params = new URLSearchParams(url.search);
        const oAuthCode = params.get("code");
        const csrfState = params.get("state");
        const csrf = await kv.get(['cookies', cookie, 'CSRF']);

        //////// Step 3: Convert the OAuth code to an OAuth token
        const response = await fetch(CONFIG.oauthTokenUrl, {
            method: "POST",
            headers: {
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                client_id: SECRETS.CLIENT_ID,
                client_secret: SECRETS.CLIENT_SECRET,
                code: oAuthCode,
            })
        });
        const data = await response.json();
        if (!data.error) {
            // SUCCESS. Foward the user back to the main page
            await kv.set(['cookies', cookie, 'token'], data.access_token);
            log(`  Saved OAuth token for ${cookie}: ${data.access_token.substring(0, 8) + ".".repeat(data.access_token.length - 8)}`);
            log(`  Sending user home.`);
            return new Response(null, {
                status: 303,
                headers: { 'Location': '/' },
            });
        }

        return new Response(`${PREFIX}
                <h1>OAuth Callback Endpoint FAILED</h1>
                <p>OAuth Code: "${oAuthCode}"</p></p>
                <p>CSRF State: "${csrfState}" ${csrfState === csrf.value ? "matches" : "does not match"} stored CSRF code "${csrf.value}".</p>
                <p>POST Response: ${JSON.stringify(data)}</p>
            ${SUFFIX}`,
            { headers: responseHeaders },
        );
    } else if (pathname === "/api/logout") {
        //////// Step 5: Revoke the OAuth token
        const authRecord = await kv.get(['cookies', cookie, 'token']);
        if (authRecord.value) {
            const response = await fetch(oauthTokenRevokeUrl, {
                method: "POST",
                headers: {
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    access_token: authRecord.value,
                })
            });
            const data = await response.json();
            if (!data.error) {
                log(`  Revoked OAuth token for ${cookie}: ${authRecord.value.substring(0, 8) + ".".repeat(authRecord.value.length - 8)}`);
                await kv.delete(['cookies', cookie, 'token']);
                log(`  Sending user home.`);

                return new Response(null, {
                    status: 303,
                    headers: { 'Location': '/' },
                });
            } else {
                log(`  Revoke OAuth token FAILED for ${cookie}: ${authRecord.value.substring(0, 8) + ".".repeat(authRecord.value.length - 8)}`);
            }
        } else {
            log(`  Cookie ${cookie} does not have OAuth token`);
        }

    }

    return new Response(
        `${PREFIX} Unhandled path ${pathname}: <pre>${JSON.stringify(Object.fromEntries(req.headers), null, 2)}</pre>${SUFFIX}`,
        {
            status: 404, headers: responseHeaders
        }
    );
}

Deno.serve({
    port: CONFIG.port,
    handler: mainHandler,
    onListen: (data) => {
        log(`HTTP server listening on ${data.hostname}:${data.port}`);
    }
});