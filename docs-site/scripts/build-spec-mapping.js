#!/usr/bin/env node
/**
 * Build Spec ID Mapping
 *
 * Scans every OpenSpec domain and maps its full spec ID (e.g. SPEC-0003)
 * to the generated Docusaurus route for that spec. Reduit numbers specs
 * sequentially across domains (all share the SPEC- prefix), so the map is
 * keyed on the full ID rather than the prefix — otherwise every SPEC-XXXX
 * cross-reference would collapse onto a single (wrong) page.
 *
 * Output: src/data/spec-mapping.json  { "SPEC-0001": "/specs/account-model/spec", ... }
 *         src/data/spec-emojis.json   { "SPEC-0001": "📐", ... }
 */

const fs = require('fs');
const path = require('path');

const SPECS_SOURCE = path.join(__dirname, '../../docs/openspec/specs');
const MAPPING_DEST = path.join(__dirname, '../src/data/spec-mapping.json');
const EMOJIS_DEST = path.join(__dirname, '../src/data/spec-emojis.json');

const SPEC_EMOJI = '📐';

function buildMapping() {
  const mapping = {};
  const emojis = {};

  fs.mkdirSync(path.dirname(MAPPING_DEST), { recursive: true });

  if (!fs.existsSync(SPECS_SOURCE)) {
    console.log('  No specs directory found, skipping spec mapping');
    fs.writeFileSync(MAPPING_DEST, JSON.stringify(mapping, null, 2));
    fs.writeFileSync(EMOJIS_DEST, JSON.stringify(emojis, null, 2));
    return mapping;
  }

  const domains = fs.readdirSync(SPECS_SOURCE);

  for (const domain of domains) {
    const domainPath = path.join(SPECS_SOURCE, domain);
    if (!fs.statSync(domainPath).isDirectory()) continue;

    const specPath = path.join(domainPath, 'spec.md');
    if (!fs.existsSync(specPath)) continue;

    const content = fs.readFileSync(specPath, 'utf-8');

    // Generated route mirrors transform-openspecs.js: paired spec+design
    // lands at /specs/<domain>/spec, a lone doc lands at /specs/<domain>.
    const hasDesign = fs.existsSync(path.join(domainPath, 'design.md'));
    const route = hasDesign ? `/specs/${domain}/spec` : `/specs/${domain}`;

    // Map the full spec ID from the H1 heading: # SPEC-0001: Title
    const h1Match = content.match(/^#\s+(SPEC-\d{3,4}):/m);
    if (h1Match) {
      mapping[h1Match[1]] = route;
      emojis[h1Match[1]] = SPEC_EMOJI;
    }
  }

  fs.writeFileSync(MAPPING_DEST, JSON.stringify(mapping, null, 2));
  fs.writeFileSync(EMOJIS_DEST, JSON.stringify(emojis, null, 2));

  console.log(`  Generated spec mapping with ${Object.keys(mapping).length} specs`);
  return mapping;
}

if (require.main === module) {
  console.log('Building spec mapping...');
  buildMapping();
}

module.exports = { buildMapping };
