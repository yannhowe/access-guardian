/**
 * Fail a pull request that edits a protected path unless it has the
 * guard-change label. Yann adds that label. An agent does not.
 */
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

/** Same paths as .github/CODEOWNERS. */
export function isProtectedPath(file) {
  const name = file.replaceAll('\\', '/').replace(/^\.\//, '');
  if (name.startsWith('src/guard/')) {
    return true;
  }
  if (name.startsWith('infra/modules/')) {
    return true;
  }
  if (name.startsWith('.github/')) {
    return true;
  }
  if (name.startsWith('.cursor/')) {
    return true;
  }
  if (name === 'src/fixes/allow-list.ts') {
    return true;
  }
  if (name.startsWith('tests/guard')) {
    return true;
  }
  return false;
}

export function findProtectedPaths(files) {
  return files.filter((file) => isProtectedPath(file));
}

/**
 * @param {string[]} files
 * @param {boolean} hasGuardLabel
 */
export function evaluate(files, hasGuardLabel) {
  const hits = findProtectedPaths(files);
  if (hits.length === 0 || hasGuardLabel) {
    return { ok: true, hits };
  }
  return { ok: false, hits };
}

export function changedFilesFromEnv(env = process.env) {
  if (env.CHANGED_FILES !== undefined) {
    return env.CHANGED_FILES.split('\n').map((line) => line.trim()).filter((line) => line.length > 0);
  }
  if (!env.BASE_SHA) {
    throw new Error('Set BASE_SHA or CHANGED_FILES.');
  }
  const head = env.HEAD_SHA && env.HEAD_SHA.length > 0 ? env.HEAD_SHA : 'HEAD';
  const out = execFileSync('git', ['diff', '--name-only', `${env.BASE_SHA}...${head}`], {
    encoding: 'utf8',
  });
  return out.split('\n').map((line) => line.trim()).filter((line) => line.length > 0);
}

function printResult(result) {
  if (result.ok && result.hits.length === 0) {
    console.log('No protected paths changed.');
    return;
  }
  if (result.ok) {
    console.log('Protected paths changed, and the guard-change label is set:');
    for (const hit of result.hits) {
      console.log(`- ${hit}`);
    }
    return;
  }
  console.error('This pull request edits a protected path:');
  for (const hit of result.hits) {
    console.error(`- ${hit}`);
  }
  console.error('Yann has to add the guard-change label before this check can pass.');
  console.error('Do not add that label yourself.');
}

function runCli() {
  let files;
  try {
    files = changedFilesFromEnv();
  } catch (err) {
    const message = err instanceof Error ? err.message : 'could not list changed files';
    console.error(message);
    process.exit(2);
  }
  const hasGuardLabel = process.env.HAS_GUARD_LABEL === 'true';
  const result = evaluate(files, hasGuardLabel);
  printResult(result);
  process.exit(result.ok ? 0 : 1);
}

const entry = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : '';
if (entry === import.meta.url || entry === pathToFileURL(fileURLToPath(import.meta.url)).href) {
  runCli();
}
