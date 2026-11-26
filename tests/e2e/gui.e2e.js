// Browser-test af hele GUI'en. Kør mod en kørende AgentWatch:
//   node tests/e2e/gui.e2e.js http://127.0.0.1:8765 [msedge]
// Exit-kode 1 hvis noget fejler. Bruges i CI mod AgentWatch.exe på Windows (Edge).
const {chromium} = require('playwright');
const B = process.argv[2] || 'http://127.0.0.1:8765';
const channel = process.argv[3];
(async () => {
  const b = await chromium.launch(channel ? {channel} : {});
  const p = await b.newPage({viewport: {width: 1300, height: 900}});
  const errs = [], fails = [];
  p.on('response', r => { if (r.status() >= 400) errs.push(r.status() + ' ' + r.url()); });
  p.on('pageerror', e => errs.push('JS ' + e.message));
  p.on('console', m => { if (m.type() === 'error') errs.push('console ' + m.text()); });
  const step = async (n, f) => {
    try { await f(); console.log('OK  ', n); }
    catch (e) { console.log('FAIL', n, e.message.split('\n')[0]); fails.push(n); }
  };
  await step('index', () => p.goto(B + '/'));
  await step('start scan (kun web, hurtig)', async () => {
    await p.selectOption('select[name=modules]', 'web'); await p.click('text=Start scanning'); });
  await step('live log', () => p.waitForSelector('#logbox >> text=/Scanning #\\d+ (startet|færdig)/', {timeout: 30000}));
  await step('scan færdig', () => p.waitForSelector('#logbox >> text=/Scanning #\\d+ færdig/', {timeout: 120000}));
  await step('ny enhed', async () => {
    await p.goto(B + '/new'); await p.fill('input[name=hostname]', 'E2E-TV');
    await p.fill('input[name=ip]', '192.168.1.250'); await p.fill('input[name=firmware]', '1.0');
    await p.click('button:text("Gem")'); await p.waitForSelector('text=Stamdata'); });
  await step('rediger', async () => {
    await p.fill('input[name=owner]', 'Alex'); await p.click('form[action="/device/edit"] button');
    if (await p.inputValue('input[name=owner]') !== 'Alex') throw Error('owner blev ikke gemt'); });
  await step('firmware', async () => {
    await p.fill('form[action="/device/firmware"] input[name=version]', '9.9'); await p.click('text=Gem firmware');
    if (await p.inputValue('form[action="/device/firmware"] input[name=version]') !== '9.9') throw Error('fw'); });
  await step('tilføj service', async () => {
    await p.fill('form[action="/device/service"] input[name=port]', '8001'); await p.click('text=+ Tilføj service');
    await p.waitForSelector('text=8001/tcp'); });
  await step('fjern service', async () => {
    await p.click('tr:has-text("8001/tcp") >> text=fjern'); await p.waitForSelector('text=Stamdata');
    if (await p.$('text=8001/tcp')) throw Error('stadig der'); });
  await step('tilføj webapp', async () => {
    await p.fill('form[action="/device/webapp"] input[name=url]', 'http://192.168.1.250/');
    await p.click('text=+ Tilføj webapp'); await p.waitForSelector('text=http://192.168.1.250/'); });
  await step('søg', async () => { await p.goto(B + '/?q=E2E&show=all'); await p.waitForSelector('text=E2E-TV'); });
  await step('slet', async () => {
    await p.click('text=192.168.1.250'); p.once('dialog', d => d.accept());
    await p.click('text=Slet enhed'); await p.waitForURL(B + '/'); });
  await step('ændringer', () => p.goto(B + '/changes'));
  await step('log-side', async () => { await p.goto(B + '/log'); await p.waitForSelector('text=/Scanning #/'); });
  await step('cve-vagt-side', async () => { await p.goto(B + '/cves'); await p.waitForSelector('text=Tjek nu'); });
  await step('diagnostik', async () => { await p.goto(B + '/diag'); await p.waitForSelector('text=nmap-version'); });
  for (const f of ['summary', 'inventory', 'cyclonedx'])
    await step('eksport ' + f, async () => { const r = await p.request.get(B + '/export/' + f);
      if (r.status() !== 200) throw Error(r.status()); });
  console.log('HTTP/JS-fejl:', errs);
  await b.close();
  process.exit(fails.length || errs.length ? 1 : 0);
})();
