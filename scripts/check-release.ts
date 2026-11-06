import { checkRelease } from './release.js';

const path = process.argv[2];
if (!path || process.argv.length !== 3) {
  console.error('Usage: pnpm check:release <release.json>');
  process.exitCode = 2;
} else {
  try {
    const result = await checkRelease(path);
    console.log(JSON.stringify({ checkedArtifacts: result.checkedArtifacts, deployment: result.manifest.deployment,
      result: 'Bundle integrity and required evidence fields passed. This check does not independently authenticate a review or ceremony.' }));
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'Release validation failed');
    process.exitCode = 1;
  }
}
