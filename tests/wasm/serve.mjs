import {createServer} from 'node:http';
import {readFile} from 'node:fs/promises';
const routes={'/':['web/proof.html','text/html; charset=utf-8'],'/meshguard.mjs':['web/meshguard.mjs','text/javascript'],'/meshguard.wasm':['zig-out/bin/meshguard.wasm','application/wasm'],
 '/relay.html':['web/relay.html','text/html; charset=utf-8'], '/relay-proof.mjs':['web/relay-proof.mjs','text/javascript'],
 '/relay-protocol.mjs':['web/relay-protocol.mjs','text/javascript'],
 '/relay-config.json':[process.env.MESHGUARD_WEB_PROOF_CONFIG || '.local/web-proof/public-config.json','application/json']};
const server=createServer(async(req,res)=>{
 const entry=routes[new URL(req.url,'http://localhost').pathname];if(!entry){res.writeHead(404);res.end();return;}
 try{const data=await readFile(entry[0]);res.writeHead(200,{'Content-Type':entry[1],'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self' wss://meshrooms.wormdb.dev; frame-ancestors 'none'"});res.end(data);}catch{res.writeHead(503);res.end('Build the WASM target and configure the public proof first.');}
});
server.listen(14339,'127.0.0.1',()=>console.log('MeshGuard WASM proof: http://127.0.0.1:14339/'));
