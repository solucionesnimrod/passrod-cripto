/**
 * Contrasta el TOTP de TypeScript contra vectores/vectores_totp.json.
 *
 * Importa el paquete YA COMPILADO (`dist/`), como verificar.mjs: lo que se
 * valida es lo que usan la web y la extensión.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  leerTotp,
  codigoTotp,
  segundosRestantesTotp,
  TotpInvalido,
} from '../dist/passrodCripto.js';

const AQUI = dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(readFileSync(join(AQUI, '..', 'vectores', 'vectores_totp.json'), 'utf8'));

let bien = 0;
let fallos = 0;
const comprobar = (nombre, ok, detalle) => {
  console.log(`${ok ? '  OK   ' : ' FALLA '}${nombre}${ok ? '' : ' — ' + detalle}`);
  ok ? bien++ : fallos++;
};

console.log('TOTP (TypeScript) contra el banco de vectores\n');

for (const c of V.codigos) {
  const obtenido = await codigoTotp(leerTotp(c.entrada), c.tiempo * 1000);
  comprobar(c.nombre, obtenido === c.esperado, `esperaba ${c.esperado}, dio ${obtenido}`);
}

for (const e of V.etiquetas) {
  const cfg = leerTotp(e.entrada);
  comprobar(e.nombre, cfg.emisor === e.emisor && cfg.cuenta === e.cuenta,
    `esperaba «${e.emisor}»/«${e.cuenta}», dio «${cfg.emisor}»/«${cfg.cuenta}»`);
}

for (const i of V.invalidos) {
  let error = null;
  try { leerTotp(i.entrada); } catch (e) { error = e; }
  comprobar(`rechaza_${i.nombre}`, error instanceof TotpInvalido && error.message.length > 0,
    error ? `lanzó ${error.name}: ${error.message}` : 'no lanzó nada');
}

// Lo que no está en el banco porque es propio de esta implementación.
const cfg = leerTotp('JBSWY3DPEHPK3PXP');
comprobar('restantes_al_empezar_periodo', segundosRestantesTotp(cfg, 1789467030_000) === 30, '');
comprobar('restantes_al_final_periodo', segundosRestantesTotp(cfg, 1789467059_999) === 1, '');
let cortado = null;
try { leerTotp('JBSWY3DPEHPK3PXPA'); } catch (e) { cortado = e; }
comprobar('rechaza_secreto_cortado', cortado instanceof TotpInvalido, String(cortado));

console.log(`\nRESULTADO: ${bien} bien, ${fallos} mal`);
process.exit(fallos ? 1 : 0);
