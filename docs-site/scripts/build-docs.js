#!/usr/bin/env node
/**
 * Build documentation content
 *
 * Orchestrates assembly of the Docusaurus content tree (docs-generated/):
 *   1. Hand-authored guides     (content/  -> docs-generated/)
 *   2. OpenSpecs                (../docs/openspec/specs -> docs-generated/specs)
 *   3. ADRs                     (../docs/adrs           -> docs-generated/decisions)
 *
 * docs-generated/ is regenerated on every build and is git-ignored.
 */

console.log('Building documentation content...\n');

// Build spec mapping first (needed by the spec/ADR cross-reference transforms)
require('./build-spec-mapping');

// Copy hand-authored guides and the landing page
require('./transform-content');

// Transform OpenSpecs
require('./transform-openspecs');

// Transform ADRs
require('./transform-adrs');

console.log('\nDocumentation content build complete!');
