import chromium from '@sparticuz/chromium';
import { chromium as pw } from 'playwright-core';
const out = process.argv[2];
const browser = await pw.launch({ args: chromium.args, executablePath: await chromium.executablePath(), headless: true });
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
const p = await ctx.newPage();
await p.goto('file://' + out + '/dist/index.html');
await p.waitForTimeout(400);

// Bring tunnel up
await p.getByRole('button', { name: 'Bring tunnel up' }).first().click();
await p.waitForTimeout(3800);

// Switch to Traffic test tab
await p.getByRole('tab', { name: /Traffic/ }).click();
await p.waitForTimeout(300);

// Screenshot default ping in interactive CLI
await p.screenshot({ path: out + '/.shots/cli-1-default.png' });

// Locate terminal input and type traceroute
const input = p.locator('input[placeholder*="type command"]');
await input.fill('traceroute 10.20.0.10');
await input.press('Enter');
await p.waitForTimeout(200);

// Type ip route
await input.fill('ip route');
await input.press('Enter');
await p.waitForTimeout(200);

// Type curl
await input.fill('curl http://10.20.0.10');
await input.press('Enter');
await p.waitForTimeout(200);

// Click quick command "arp -n"
await p.getByRole('button', { name: 'arp -n' }).click();
await p.waitForTimeout(200);

// Screenshot interactive session
await p.screenshot({ path: out + '/.shots/cli-2-interactive.png' });

await browser.close();
console.log('CLI tested successfully');
