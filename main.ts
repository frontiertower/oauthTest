/*
Minimal demo of Frontier Tower OAuth

To use:
  1. `export CLIENT_SECRET=154b....`
  2. `export CLIENT_ID=F5ojGQ...`
  3. `export REDIRECT_URI=https://.../api/oauth`
  4. Run `deno run --allow-net --allow-read --allow-write --unstable-kv --watch ./main.ts 3141`
  5. Auth & deauth
  6. The webapp also has basic notes functionality that is preserved across sessions for a given user.

Design:
  0. Identify the browser with a cookie.
  1.  Check if that cookie has an OAuth Token in KV
  2.  Create a login page
  3. Convert the OAuth code to an OAuth token
  4. Get some useful private data from the API.
  5. Save data to KV for authenticated users
  6. Revoke the OAuth token
*/
//////// deno run --allow-net --allow-read --allow-write --unstable-kv --watch ./main.ts 3141

const start = Date.now();
function log(msg: string) {
    const prefix = ((Date.now() - start) / 1000).toFixed(3) + "> ";
    console.log(prefix + msg);
}

const CONFIG = {
    port: parseInt(Deno.args.at(0) || "9002"),

    REDIRECT_URI: `https://9000-firebase-oauthtest-1755815235789.cluster-cmxrewsem5htqvkvaud2drgfr4.cloudworkstations.dev/api/oauth`, // Url of the app server that recieves the callback from Oauth server.
    oauthAuthorizeUrl: "https://api.berlinhouse.com/o/authorize/", // Oauth server's auth endpoint for step 2
    oauthTokenUrl: "https://api.berlinhouse.com/o/token/", // OAuth server POST endpoint for step 3
    oauthRevokeUrl: "https://api.berlinhouse.com/o/revoke_token/", // OAuth call to revoke token from step 6
    callbackPath: "/api/oauth",
}
const SECRETS = Deno.env.toObject();
if (new URL(SECRETS.REDIRECT_URI).pathname !== CONFIG.callbackPath) {
    throw Error(`CONFIG redirect_uri's path "${SECRETS.REDIRECT_URI}" must match callbackPath "${CONFIG.callbackPath}"`);
}

log(`Booting @ ${new Date()} with ${JSON.stringify(SECRETS, null, 2)} ${JSON.stringify(CONFIG, null, 2)}`);

const kv = await Deno.openKv(); // Deno key-value store.

function generate_code_verifier(): string {
    const array = new Uint8Array(64); // 64 bytes for 512 bits of entropy
    crypto.getRandomValues(array);
    // Base64 URL-safe encode without padding
    return btoa(String.fromCharCode(...array))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

async function generate_code_challenge(code_verifier: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(code_verifier);
    // SHA-256 hash
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    // Convert buffer to byte array
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    // Convert byte array to binary string
    const binaryString = hashArray.map(byte => String.fromCharCode(byte)).join('');
    // Base64 URL-safe encode without padding
    return btoa(binaryString)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}





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

    //////// Define HTTP endpoints for "/" and "/api/*"
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
            const headers = {
                "Accept": "application/json",
                "Authorization": `${authRecord.value.token_type} ${authRecord.value.access_token}`,
            }

            const response = await fetch(`https://api.berlinhouse.com/o/userinfo/`, {
                headers
            });
            const json = await response.json();
            const uid = json.sub;
            kv.set(['cookies', cookie, 'id'], uid);

            const data = await kv.get(['database', uid, 'data']);

            return new Response(`${PREFIX}
                    <h1>OAuth User Page for User ${uid}</h1>
                    <p>Cookie: ${cookie}</p>
                    <p><b>API call to <code>https://api.berlinhouse.com/o/userinfo/</code>: ${response.status === 200 ? "SUCCESS" : "FAILED"}</b></p>
                    <pre>${JSON.stringify(json, null, 2)}</pre>
                    <textarea id="data" rows=10 cols=50>${data.value}</textarea>
                    <br/>
                    <button onclick="save()">Save</button>
                    <button onclick="logout()">Log out</button>
                    <br/>
                    <script>
                        async function save() {
                            const data = document.getElementById('data').value;
                            const response = await fetch('/api/kv', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'text/plain',
                                },
                                body: data,
                            });
                            if (response.ok) {
                                console.log('Data saved successfully!');
                            } else {
                                console.error('Failed to save data:', response.status);
                            }
                        }

                        async function logout() {
                            const response = await fetch('/api/logout', {method: 'POST'});
                            window.location.href = '/';
                        }
                    </script>
                    ${SUFFIX}`,
                { headers: responseHeaders },
            );
        } else {
            //////// Step 2:  Create a login page
            const CSRF = crypto.randomUUID();  // https://en.wikipedia.org/wiki/Cross-site_request_forgery
            await kv.set(['cookies', cookie, 'CSRF'], CSRF);
            log(`  Saved CSRF for ${cookie}: ${CSRF}`);

            const code_verifier = await generate_code_verifier();
            await kv.set(['cookies', cookie, 'code_verifier'], code_verifier);
            const code_challenge = await generate_code_challenge(code_verifier);

            const oAuthLoginLink =
                `${CONFIG.oauthAuthorizeUrl}` +
                `?response_type=code` +
                `&client_id=${SECRETS.CLIENT_ID}` +
                `&redirect_uri=${encodeURIComponent(SECRETS.REDIRECT_URI)}` +
                `&scope=read write openid` +
                `&state=${CSRF}` +
                `&code_challenge=${code_challenge}` +
                `&code_challenge_method=S256`;

            return new Response(`${PREFIX}
                    <h1>OAuth Login Page</h1>
                    <p>Cookie ${cookie} not authenticated.</p>
                    <a href="${oAuthLoginLink}">Login with FT</a>
                ${SUFFIX}`,
                { headers: responseHeaders },
            );
        }
    } else if (pathname === CONFIG.callbackPath) {
        const params = new URLSearchParams(url.search);
        const oAuthCode = params.get("code");
        const codeVerifierRecord = await kv.get(['cookies', cookie, 'code_verifier']);
        const code_verifier = codeVerifierRecord.value;
        const csrfState = params.get("state");
        const csrf = await kv.get(['cookies', cookie, 'CSRF']);

        //////// Step 3: Convert the OAuth code to an OAuth token
        const body = new URLSearchParams({
            'grant_type': 'authorization_code',
            'code': oAuthCode!, // Use non-null assertion as code should be present
            'redirect_uri': SECRETS.REDIRECT_URI,
            'client_id': SECRETS.CLIENT_ID,
            'client_secret': SECRETS.CLIENT_SECRET,
            'code_verifier': code_verifier!, // Use non-null assertion as code_verifier should be present
        }).toString();
        log(`  Token exchange request body: ${body}`);

        const response = await fetch(CONFIG.oauthTokenUrl, {

            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body
        });
        const data = await response.json();
        if (!data.error) {
            // SUCCESS. Foward the user back to the main page
            await kv.set(['cookies', cookie, 'token'], data);
            log(`  Saved OAuth token for ${cookie}: ${data.access_token.substring(0, 8) + ".".repeat(data.access_token.length - 8)}`);
            log(`  Sending user home.`);
            return new Response(null, {
                status: 303,
                headers: { 'Location': '/' },
            });
        }

        return new Response(`${PREFIX}
                <h1>OAuth Callback Endpoint FAILED</h1>
                <p>CSRF State: "${csrfState}" ${csrfState === csrf.value ? "matches" : "does not match"} stored CSRF code "${csrf.value}".</p>
                <p>POST Response: ${JSON.stringify(data)}</p>
            ${SUFFIX}`,
            { headers: responseHeaders },
        );
    } else if (pathname === "/api/logout" && req.method === "POST") {
        //////// Step 6: Revoke the OAuth token
        const authRecord = await kv.get(['cookies', cookie, 'token']);
        if (authRecord.value) {
            await kv.delete(['cookies', cookie, 'token']);
            const response = await fetch(CONFIG.oauthRevokeUrl, {
                method: "POST",
                headers: {
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
                log(`  Revoke OAuth token FAILED for ${cookie}`);
                return new Response("Logout failed", { status: 500 });
            }
        } else {
            log(`  Cookie ${cookie} does not have OAuth token`);
            return new Response(null, { // Redirect even if no token was found for logout
                status: 303,
                headers: { 'Location': '/' },
            });
        }
    } else if (pathname === "/api/kv" && req.method === "POST") {
        //////// Step 5: Save data to KV for authenticated users
        const authRecord = await kv.get(['cookies', cookie, 'token']);
        if (authRecord.value) {
            const uidRecord = await kv.get(['cookies', cookie, 'id']);
            const uid = uidRecord.value;
            if (uid) {
                const data = await req.text();
                await kv.set(['database', uid, 'data'], data);
                log(`  Saved data for user ${uid}`);
                return new Response("Data saved", { status: 200 });
            } else {
                log(`  User ${cookie} is authenticated but no uid found`);
                return new Response("User ID not found", { status: 401 });
            }
        } else {
            log(`  User ${cookie} is not authenticated for /api/kv`);
            return new Response("Unauthorized", { status: 401 });
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