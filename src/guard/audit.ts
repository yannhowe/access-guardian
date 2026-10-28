/**
 * Static checks for the hard gates.
 *
 * A fix file under src/fixes (other than the allow-list and the registry)
 * must be on the allow-list and must declare exactly one ACTION.
 * A mutating API name in src must be that allow-listed action, in the
 * allow-list, the registry, the catalog, or the fix that owns it.
 * The xAI endpoint, the chat completions path, and the key and model env
 * names may appear only in the Grok client and its unit test.
 *
 * Tokens below are split so this file does not contain the token it searches for.
 */

export type SourceFile = {
  path: string;
  text: string;
};

export type AuditRules = {
  allowList: Readonly<Record<string, { readonly action: string }>>;
  mutatingApis: readonly string[];
  xaiMarkers: readonly string[];
  grokClientPath: string;
  xaiAllowedPaths: readonly string[];
  catalogPath: string;
};

export type AuditFailure = {
  path: string;
  message: string;
};

const FORBIDDEN_TOKENS = [
  'child' + '_process',
  'exec' + 'Sync',
  'spawn' + 'Sync',
  'spawn' + '(',
  'eval' + '(',
  'new ' + 'Function',
  'import' + '(',
] as const;

/** A shell `exec` call. A dotted `RegExp.exec` does not match. */
const BARE_EXEC = /(?:^|[^.\w])exec\s*\(/;

const EXTRACT_CALL = 'extract' + '(';

const FIX_PATH = /^src\/fixes\/([a-z0-9]+(?:-[a-z0-9]+)*)\.ts$/;
const NON_FIX = new Set(['allow-list', 'registry']);
const ACTION_EXPORT = /export const ACTION = '([A-Za-z0-9]+)' as const;/g;
const COMMAND_CONSTRUCTOR = /new\s+([A-Z][A-Za-z0-9]*)Command\b/g;
const READ_COMMAND = /^(Describe|List|Get)/;

export function audit(files: readonly SourceFile[], rules: AuditRules): AuditFailure[] {
  const failures: AuditFailure[] = [];
  const allowedActions = new Set(Object.values(rules.allowList).map((entry) => entry.action));

  for (const [key, entry] of Object.entries(rules.allowList)) {
    if (!rules.mutatingApis.includes(entry.action)) {
      failures.push({
        path: 'src/fixes/allow-list.ts',
        message: `allow-list action ${entry.action} for ${key} is not in the mutating API catalog`,
      });
    }
  }

  for (const file of files) {
    if (!rules.xaiAllowedPaths.includes(file.path)) {
      for (const marker of rules.xaiMarkers) {
        if (marker.length > 0 && file.text.includes(marker)) {
          failures.push({
            path: file.path,
            message: `xAI call marker outside the Grok client: ${marker}`,
          });
        }
      }
    }

    if (file.path.startsWith('src/')) {
      for (const token of FORBIDDEN_TOKENS) {
        if (file.text.includes(token)) {
          failures.push({
            path: file.path,
            message: `forbidden token: ${token}`,
          });
        }
      }
      if (BARE_EXEC.test(file.text)) {
        failures.push({
          path: file.path,
          message: 'forbidden token: ' + 'exec' + '(',
        });
      }
    }

    scanCommands(file, allowedActions, failures);

    if (file.path.startsWith('src/') && file.path !== rules.grokClientPath && file.text.includes(EXTRACT_CALL)) {
      if (!file.text.includes('What Grok decides:')) {
        failures.push({
          path: file.path,
          message: 'Grok call is missing a "What Grok decides:" note',
        });
      }
      if (!file.text.includes('What code decides:')) {
        failures.push({
          path: file.path,
          message: 'Grok call is missing a "What code decides:" note',
        });
      }
    }

    const fixName = fixKey(file.path);
    if (fixName !== undefined) {
      scanFix(file, fixName, rules, failures);
      continue;
    }

    if (!file.path.startsWith('src/') || file.path === rules.catalogPath) {
      continue;
    }

    const mentioned = apisIn(file.text, rules.mutatingApis);
    const mayNameActions = file.path === 'src/fixes/allow-list.ts' || file.path === 'src/fixes/registry.ts';
    for (const api of mentioned) {
      if (!allowedActions.has(api)) {
        failures.push({
          path: file.path,
          message: `mutating call ${api} is not on the allow-list`,
        });
      } else if (!mayNameActions) {
        failures.push({
          path: file.path,
          message: `mutating call ${api} appears outside its fix`,
        });
      }
    }
  }

  return failures;
}

function scanFix(
  file: SourceFile,
  key: string,
  rules: AuditRules,
  failures: AuditFailure[],
): void {
  const entry = rules.allowList[key];
  if (entry === undefined) {
    failures.push({
      path: file.path,
      message: `fix ${key} is not on the allow-list`,
    });
  }

  const declared = [...file.text.matchAll(ACTION_EXPORT)].map((match) => match[1]).filter((name) => name !== undefined);
  if (declared.length !== 1) {
    failures.push({
      path: file.path,
      message: `fix ${key} declares ${declared.length} actions`,
    });
  } else if (entry !== undefined && declared[0] !== entry.action) {
    failures.push({
      path: file.path,
      message: `fix ${key} action ${declared[0]} does not match allow-list action ${entry.action}`,
    });
  }

  const sends = file.text.match(/\.send\(/g) ?? [];
  if (sends.length !== 1) {
    failures.push({
      path: file.path,
      message: `fix ${key} has ${sends.length} client send sites`,
    });
  }

  const mentioned = apisIn(file.text, rules.mutatingApis);
  if (entry !== undefined && !mentioned.includes(entry.action)) {
    failures.push({
      path: file.path,
      message: `fix ${key} does not name its allow-list action`,
    });
  }
  const extras = mentioned.filter((api) => api !== entry?.action);
  if (extras.length > 0 || mentioned.length > 1) {
    failures.push({
      path: file.path,
      message: `fix ${key} names more than one action: ${mentioned.join(', ')}`,
    });
  }
}

function scanCommands(file: SourceFile, allowedActions: ReadonlySet<string>, failures: AuditFailure[]): void {
  for (const match of file.text.matchAll(COMMAND_CONSTRUCTOR)) {
    const name = match[1];
    if (name === undefined || READ_COMMAND.test(name)) {
      continue;
    }
    if (!allowedActions.has(name)) {
      failures.push({
        path: file.path,
        message: `mutating command ${name}Command is not on the allow-list`,
      });
    }
  }
}

function fixKey(path: string): string | undefined {
  const match = FIX_PATH.exec(path);
  const key = match?.[1];
  if (key === undefined || NON_FIX.has(key)) {
    return undefined;
  }
  return key;
}

function apisIn(text: string, apis: readonly string[]): string[] {
  const found: string[] = [];
  for (const api of apis) {
    const pattern = new RegExp(`\\b${api}\\b`);
    if (pattern.test(text)) {
      found.push(api);
    }
  }
  return found;
}
