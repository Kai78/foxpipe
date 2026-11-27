import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import http from 'node:http';
import express from 'express';

const EXTERNAL_PORT = Number(process.env.DEFAULT_APP_PORT || 3000);
const PYTHON_HOST = '127.0.0.1';
const PYTHON_PORT = 8090;

let pythonProcess: ChildProcess | null = null;

function stopStalePythonProcesses(): void {
  try {
    spawnSync('pkill', ['-TERM', '-f', 'python3.11 run.py'], { stdio: 'ignore' });
  } catch {
    // ignore if pkill is unavailable or no matching process exists
  }
}

function startPythonServer(): ChildProcess {
  stopStalePythonProcesses();
  const childEnv: NodeJS.ProcessEnv = {
    ...process.env,
    PYTHON_HOST,
    PYTHON_PORT: String(PYTHON_PORT),
  };
  if (childEnv.RUNNER_CONFIG_PATH === '/etc/foxpipe') delete childEnv.RUNNER_CONFIG_PATH;
  if (childEnv.RUNNER_DB_PATH === '/var/foxpipe') delete childEnv.RUNNER_DB_PATH;
  if (childEnv.ADMIN_PASSCODE === '12345') delete childEnv.ADMIN_PASSCODE;
  if (childEnv.LDAP_BIND_PASSWORD === '12345') delete childEnv.LDAP_BIND_PASSWORD;

  const child = spawn('python3.11', ['run.py'], {
    env: childEnv,
    stdio: 'inherit',
  });

  child.on('exit', (code, signal) => {
    if (code !== null && code !== 0) {
      console.error(`Python 3.11 server exited with code ${code}`);
    } else if (signal) {
      console.log(`Python 3.11 server terminated by signal ${signal}`);
    }
  });

  return child;
}

async function waitForPythonHealth(timeoutMs = 15000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const ok = await new Promise<boolean>((resolve) => {
        const req = http.get(
          { host: PYTHON_HOST, port: PYTHON_PORT, path: '/api/health', timeout: 1000 },
          (res) => {
            res.resume();
            resolve(res.statusCode === 200);
          },
        );
        req.on('error', () => resolve(false));
        req.on('timeout', () => {
          req.destroy();
          resolve(false);
        });
      });
      if (ok) return;
    } catch {
      // retry until healthy
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('Timed out waiting for Python 3.11 FastAPI server.');
}

async function bootstrap() {
  pythonProcess = startPythonServer();
  await waitForPythonHealth();

  const app = express();

  const HOP_BY_HOP_HEADERS = new Set([
    'connection',
    'upgrade',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'proxy-connection',
    'te',
    'trailers',
    'transfer-encoding',
  ]);

  app.use((req, res) => {
    const forwardHeaders: http.OutgoingHttpHeaders = {};
    for (const [key, value] of Object.entries(req.headers)) {
      const lower = key.toLowerCase();
      if (!HOP_BY_HOP_HEADERS.has(lower) && value !== undefined) {
        forwardHeaders[key] = value;
      }
    }
    forwardHeaders.host = `${PYTHON_HOST}:${PYTHON_PORT}`;
    if (!forwardHeaders['x-forwarded-host'] && req.headers.host) {
      forwardHeaders['x-forwarded-host'] = req.headers.host;
    }

    const proxyReq = http.request(
      {
        host: PYTHON_HOST,
        port: PYTHON_PORT,
        path: req.originalUrl,
        method: req.method,
        headers: forwardHeaders,
      },
      (proxyRes) => {
        res.status(proxyRes.statusCode || 502);
        for (const [key, value] of Object.entries(proxyRes.headers)) {
          const lower = key.toLowerCase();
          if (!HOP_BY_HOP_HEADERS.has(lower) && value !== undefined) {
            res.setHeader(key, value);
          }
        }
        proxyRes.pipe(res);
      },
    );

    proxyReq.on('error', (err) => {
      if (!res.headersSent) {
        res.status(502).json({ error: 'Python backend unavailable', detail: err.message });
      }
    });

    req.pipe(proxyReq);
  });

  const server = app.listen(EXTERNAL_PORT, '0.0.0.0', () => {
    console.log(`Proxy listening on http://0.0.0.0:${EXTERNAL_PORT} -> Python 3.11 http://${PYTHON_HOST}:${PYTHON_PORT}`);
  });

  const shutdown = () => {
    server.close();
    if (pythonProcess && !pythonProcess.killed) {
      pythonProcess.kill('SIGTERM');
    }
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

bootstrap().catch((err) => {
  console.error('Failed to start server:', err);
  if (pythonProcess && !pythonProcess.killed) {
    pythonProcess.kill('SIGTERM');
  }
  process.exit(1);
});
