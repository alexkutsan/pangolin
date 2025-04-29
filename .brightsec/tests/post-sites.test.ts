import { test, before, after } from 'node:test';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';
import { SecRunner } from '@sectester/runner';

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

test('POST /sites', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'bopla', 'sqli', 'xss', 'secret_tokens', 'osi'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.QUERY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/sites`,
      body: {
        name: "Example Site",
        type: "wireguard",
        exitNodeId: 1,
        pubKey: "examplePublicKey",
        subnet: "192.168.1.0/24",
        newtId: "exampleNewtId",
        secret: "exampleSecret"
      },
      query: {
        orgId: "example-org-id"
      },
      headers: { 'Content-Type': 'application/json' }
    });
});
