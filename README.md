Minimal demo of Frontier Tower OAuth

1. Generate a .secrets.json file
2. Run `deno run --allow-net --allow-read --allow-write --unstable-kv --watch ./main.ts 3141`
3. Go to the server and make sure the server matches `REDIRECT_URI` in `.secrets.json`.
4. Auth & deauth
5. The webapp also has basic notes functionality that is preservered across sessions for a given user.

This currently uses GitHub APIs as a placeholder for FT APIs. It also doen't test refresh.
