// Заливка пакета L3 в Arweave через Turbo (@ardrive/turbo-sdk).
// Зовётся из anchor.py:  node turbo_upload.mjs <файл> <кошелёк.json> '<теги JSON>' [<каталог node_modules с turbo-sdk>]
// Турбо грузит бесплатно всё меньше 100 КиБ; порог проверяет anchor.py до вызова.
// Ключ кошелька читается из файла и никуда не печатается. Вывод — одна строка JSON {"id": "..."}.
import { readFileSync } from 'node:fs';
import { Readable } from 'node:stream';
import { createRequire } from 'node:module';
import path from 'node:path';

const [file, walletPath, tagsJson, sdkDir] = process.argv.slice(2);
if (!file || !walletPath) {
  console.error('нужно: <файл> <кошелёк.json> [теги] [каталог sdk]');
  process.exit(2);
}
const require = createRequire(sdkDir ? path.join(sdkDir, 'noop.js') : import.meta.url);
const { TurboFactory } = require('@ardrive/turbo-sdk');

const data = readFileSync(file);
const jwk = JSON.parse(readFileSync(walletPath, 'utf8'));
const tags = Object.entries(JSON.parse(tagsJson || '{}')).map(([name, value]) => ({ name, value: String(value) }));
const turbo = TurboFactory.authenticated({ privateKey: jwk });
const res = await turbo.uploadFile({
  fileStreamFactory: () => Readable.from(data),
  fileSizeFactory: () => data.length,
  dataItemOpts: { tags },
});
console.log(JSON.stringify({ id: res.id }));
