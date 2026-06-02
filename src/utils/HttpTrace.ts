import { appendFileSync, mkdirSync } from 'fs';
import path from 'path';

import { CONFIG } from './ArgConfig';
import { dataToXMLBuffer } from './KBinJSON';
import { Logger } from './Logger';

const EXEC_PATH = path.resolve((process as any).pkg ? path.dirname(process.argv0) : process.cwd());
const TRACE_DIR = path.join(EXEC_PATH, 'logs', 'http_trace');

function traceEnabled() {
  return CONFIG.http_trace_logging === true || CONFIG.http_trace_logging === 'true';
}

function serializePayload(payload: any) {
  try {
    return dataToXMLBuffer(payload, 'utf8').toString('utf8');
  } catch (err) {
    return JSON.stringify(payload, null, 2);
  }
}

export function appendHttpTrace(
  direction: 'request' | 'response',
  route: string,
  payload: any
) {
  if (!traceEnabled()) {
    return;
  }

  try {
    mkdirSync(TRACE_DIR, { recursive: true });
    const file = path.join(TRACE_DIR, `${route}.txt`);
    const body = serializePayload(payload);
    appendFileSync(
      file,
      [
        `===== ${direction.toUpperCase()} ${route} ${new Date().toISOString()} =====`,
        body,
        '',
      ].join('\r\n'),
      { encoding: 'utf8' }
    );
  } catch (err) {
    Logger.error(err);
  }
}
