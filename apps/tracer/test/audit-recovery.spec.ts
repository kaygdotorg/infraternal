/** Defensive recovery transport probe; public fixture words only, never print request payloads. */
import { expect, test } from 'playwright/test';
import { entropyToMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
test('audit recovery words remain inside the browser', async ({ page }) => {
  let sentPlaintext = false, correctVerifier = false;
  const publicEntropy = new Uint8Array(32).fill(1);
  const key = await crypto.subtle.importKey('raw', publicEntropy, 'HKDF', false, ['deriveBits']);
  const expectedVerifier = Buffer.from(await crypto.subtle.deriveBits({ name:'HKDF', hash:'SHA-256', salt:new ArrayBuffer(0), info:new TextEncoder().encode('infraternal/recovery/auth/v2') },key,256)).toString('base64url');
  await page.route('**/auth/status', route => route.fulfill({json:{setup_required:false}}));
  await page.route('**/auth/session', route => route.fulfill({status:401,json:{}}));
  await page.route('**/auth/recovery-resume', route => {
    const body = route.request().postDataJSON();
    correctVerifier = body.verifier === expectedVerifier && Object.keys(body).sort().join(',') === 'username,verifier';
    sentPlaintext = typeof body.words === 'string' && body.words.split(' ').length === 24;
    return route.fulfill({status:401,json:{error:'authorization failed'}});
  });
  await page.goto('/');
  await page.getByRole('button',{name:'use recovery key',exact:true}).click();
  await page.locator('#recovery-username').fill('fixture_owner');
  const phrase = entropyToMnemonic(new Uint8Array(32).fill(1),wordlist);
  await page.getByRole('textbox',{name:'Word 1',exact:true}).evaluate((input,value)=>{
    const clipboardData = new DataTransfer(); clipboardData.setData('text/plain',value);
    input.dispatchEvent(new ClipboardEvent('paste',{clipboardData,bubbles:true,cancelable:true}));
  },phrase);
  await page.getByRole('button',{name:'Start recovery'}).click();
  await expect(page.locator('#auth-error')).toContainText('Recovery could not start');
  expect(sentPlaintext,'recovery-start contains readable 24-word phrase in JSON').toBe(false);
  expect(correctVerifier,'browser sends only the contract HKDF authentication sibling').toBe(true);
});

test('already-upgraded key never retransmits words when older-key option is selected', async ({ page }) => {
  let phraseRequests = 0;
  await page.route('**/auth/status', route => route.fulfill({json:{setup_required:false}}));
  await page.route('**/auth/session', route => route.fulfill({status:401,json:{}}));
  await page.route('**/auth/recovery-upgrade', route => {
    phraseRequests++;
    return route.fulfill({status:401,json:{error:'authorization failed'}});
  });
  await page.route('**/auth/recovery-resume', route => route.fulfill({json:{token:'public-upgraded-fixture',ready_at:Math.floor(Date.now()/1000)+3600,delay_seconds:3600}}));
  await page.goto('/');
  await page.getByRole('button',{name:'use recovery key',exact:true}).click();
  await page.locator('#recovery-username').fill('fixture_owner');
  const phrase = entropyToMnemonic(new Uint8Array(32).fill(1),wordlist);
  await page.getByRole('textbox',{name:'Word 1',exact:true}).evaluate((input,value)=>{
    const clipboardData=new DataTransfer(); clipboardData.setData('text/plain',value);
    input.dispatchEvent(new ClipboardEvent('paste',{clipboardData,bubbles:true,cancelable:true}));
  },phrase);
  await page.getByText('Upgrade an older recovery key',{exact:true}).click();
  await page.getByRole('button',{name:'Start recovery'}).click();
  await expect(page.getByRole('heading',{name:'Recovery started'})).toBeVisible();
  expect(phraseRequests).toBe(0);
});
