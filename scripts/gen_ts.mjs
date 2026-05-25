import { compileFromFile } from 'json-schema-to-typescript';
import { writeFileSync } from 'fs';

const banner = `/* eslint-disable */
/**
 * AUTO-GENERATED from sailor.schema.json. DO NOT EDIT.
 * Run scripts/regen_contracts.sh to regenerate.
 *
 * This file is the single source of truth for all types shared
 * between the Sailor frontend and backend. Import types from here;
 * do NOT redefine them in lib/types.ts or anywhere else.
 */
`;

const ts = await compileFromFile('shared/contracts/sailor.schema.json', {
  bannerComment: banner,
  declareExternallyReferenced: true,
  unreachableDefinitions: true,
  additionalProperties: false,
  style: { singleQuote: true, semi: true, tabWidth: 2 },
});

writeFileSync('shared/contracts/sailor.types.ts', ts);
console.log('Wrote shared/contracts/sailor.types.ts');
