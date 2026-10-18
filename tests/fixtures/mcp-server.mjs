import { createServer } from 'node:http';
import { Server, createMcpHandler } from '@modelcontextprotocol/server';
import { toNodeHandler } from '@modelcontextprotocol/node';

let calls = 0;
const handler = createMcpHandler(() => {
  const server = new Server({ name: 'compose-fixture', version: '1' }, { capabilities: { tools: {} } });
  server.setRequestHandler('tools/list', () => ({ tools: [
    { name: 'read_echo', description: 'Read-only local integration fixture', inputSchema: { type: 'object', properties: { text: { type: 'string', maxLength: 1000 } }, required: ['text'], additionalProperties: false } },
    { name: 'write_echo', description: 'Local write approval integration fixture', inputSchema: { type: 'object', properties: { text: { type: 'string', maxLength: 1000 } }, required: ['text'], additionalProperties: false } },
  ] }));
  server.setRequestHandler('tools/call', request => {
    calls++;
    return { content: [{ type: 'text', text: JSON.stringify({ text: request.params.arguments.text, calls }) }] };
  });
  return server;
});
const nodeHandler = toNodeHandler(handler);
createServer((request, response) => {
  if (request.headers.authorization !== 'Bearer local-fixture-credential') {
    response.writeHead(401); response.end(); return;
  }
  void nodeHandler(request, response);
}).listen(8081, '0.0.0.0');
