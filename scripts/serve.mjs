/**
 * Zero-dependency static file server for local development.
 *
 *   npm run serve      ->  http://localhost:5173
 *
 * The site is plain files, so you can also just open docs/index.html directly —
 * but a real origin makes it behave the same as it will on GitHub Pages, which
 * matters because the Arc RPC is queried cross-origin from the browser.
 */

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("../docs", import.meta.url)));
const port = Number(process.env.PORT ?? 5173);

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    let pathname = decodeURIComponent(url.pathname);
    if (pathname === "/") pathname = "/index.html";

    // Contain every request inside docs/.
    const target = join(root, normalize(pathname).replace(/^(\.\.[/\\])+/, ""));
    if (!target.startsWith(root)) {
      res.writeHead(403).end("forbidden");
      return;
    }

    const body = await readFile(target);
    res.writeHead(200, {
      "content-type": TYPES[extname(target)] ?? "application/octet-stream",
      "cache-control": "no-store",
    });
    res.end(body);
  } catch (error) {
    if (error.code === "ENOENT" || error.code === "EISDIR") {
      res.writeHead(404, { "content-type": "text/plain" }).end("not found");
      return;
    }
    res.writeHead(500, { "content-type": "text/plain" }).end(String(error.message));
  }
});

server.listen(port, () => {
  console.log(`Arc Guard -> http://localhost:${port}`);
  console.log(`serving ${root}`);
});
