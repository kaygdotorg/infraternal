/** Independent hard-requirement probe: public fixture only; never print payloads. */
import { expect, test } from 'playwright/test';
import { entropyToMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
test('reviewer: explicit legacy path must satisfy absolute words non-disclosure', async ({page}) => {
  let leaked = false;
  await page.route('**/auth/status', r => r.fulfill({json:{setup_required:false}}));
  await page.route('**/auth/session', r => r.fulfill({status:401,json:{}}));
  await page.route('**/auth/recovery-resume', r => r.fulfill({status:401,json:{error:'authorization failed'}}));
  await page.route('**/auth/recovery-upgrade', r => {
    const body = r.request().postDataJSON();
    leaked = body.words === entropyToMnemonic(new Uint8Array(32).fill(1),wordlist);
    return r.fulfill({status:401,json:{error:'authorization failed'}});
  });
  await page.goto('/');
  await page.getByRole('button',{name:'use recovery key',exact:true}).click();
  await page.locator('#recovery-username').fill('fixture_owner');
  await page.getByRole('textbox',{name:'Word 1',exact:true}).evaluate(input => {
    const clipboardData=new DataTransfer();
    // Standard public 256-bit BIP-39 test fixture; contains no account secret.
    clipboardData.setData('text/plain','absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice comic');
    input.dispatchEvent(new ClipboardEvent('paste',{clipboardData,bubbles:true,cancelable:true}));
  });
  await expect(page.getByText('Upgrade an older recovery key',{exact:true})).toHaveCount(0);
  await page.getByRole('button',{name:'Start recovery'}).click();
  await expect(page.locator('#auth-error')).not.toHaveText('');
  console.log(`REVIEW phrase_disclosed=${leaked}`);
  expect(leaked,'hard requirement: words must never reach server').toBe(false);
});

test('reviewer: preserved deadline remains resumable after server clock rollback', async ({page}) => {
  await page.route('**/auth/status', r => r.fulfill({json:{setup_required:false}}));
  await page.route('**/auth/session', r => r.fulfill({status:401,json:{}}));
  await page.route('**/auth/recovery-resume', r => r.fulfill({json:{token:'public-rollback-fixture',ready_at:Math.floor(Date.now()/1000)+90000,delay_seconds:90000}}));
  await page.goto('/');
  await page.getByRole('button',{name:'use recovery key',exact:true}).click();
  await page.locator('#recovery-username').fill('fixture_owner');
  await page.getByRole('textbox',{name:'Word 1',exact:true}).evaluate(input => {
    const clipboardData=new DataTransfer();
    clipboardData.setData('text/plain','absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice comic');
    input.dispatchEvent(new ClipboardEvent('paste',{clipboardData,bubbles:true,cancelable:true}));
  });
  await page.getByRole('button',{name:'Start recovery'}).click();
  await expect(page.getByRole('heading',{name:'Recovery started'})).toBeVisible();
});
