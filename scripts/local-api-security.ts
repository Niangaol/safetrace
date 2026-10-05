import type{IncomingMessage}from"node:http";
export function allowedLocalHost(req:IncomingMessage):boolean {const host=req.headers.host;if(typeof host!=="string"||host.length>200||/[\s/@#?]/.test(host))return false;try{const u=new URL("http://"+host);return ["127.0.0.1","localhost","[::1]"].includes(u.hostname)&&Number(u.port||80)===req.socket.localPort;}catch{return false;}}
