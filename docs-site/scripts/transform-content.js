#!/usr/bin/env node
/**
 * Copy hand-authored content into the generated docs tree.
 *
 * Everything under docs-site/content/ is copied verbatim into
 * docs-generated/ (the Docusaurus `docs.path`). This is where the
 * landing page (overview.md) and the Guides section live — content
 * that is written by hand rather than transformed from ../docs.
 */

const fs = require('fs');
const path = require('path');

const CONTENT_SOURCE = path.join(__dirname, '../content');
const DEST = path.join(__dirname, '../../docs-generated');

function copyDir(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDir(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

function main() {
  console.log('Copying hand-authored content...');

  if (!fs.existsSync(CONTENT_SOURCE)) {
    console.log('  No content/ directory found, skipping');
    return;
  }

  fs.mkdirSync(DEST, { recursive: true });
  copyDir(CONTENT_SOURCE, DEST);

  let count = 0;
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(p);
      else if (entry.name.endsWith('.md') || entry.name.endsWith('.mdx')) count++;
    }
  };
  walk(CONTENT_SOURCE);

  console.log(`  Copied ${count} hand-authored doc files`);
}

main();
