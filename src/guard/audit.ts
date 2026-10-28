/**
 * Static checks for the hard gates.
 *
 * Each fix folder has a handler, a policy, metadata, and a test, and the
 * folder is on the allow-list. Mutating policy actions must be on the
 * close-only list. Patterns that open or delete are blocked even if someone
 * adds them to that list. Handlers may only construct SDK commands for
 * actions the policy lists. Every allow-listed handler declares the
 * auto-remediate tag key and value, and calls hasAutoRemediateTag( before
 * its one mutating send. The two bucket public access block fixes also
 * check public before that send. remove-bucket-public-access-block
 * requires the tag to be present. restore-bucket-public-access-block
 * requires the tag to be absent.
 *
 * DeletePublicAccessBlockCommand and DeleteBucketPublicAccessBlockCommand
 * are blocked in every handler. The one exception is
 * src/fixes/remove-bucket-public-access-block/handler.ts, and only when
 * that handler checks public=true, auto-remediate=true, and
 * purpose=ag-demo-synthetic before the send. The checks are exact and
 * case-sensitive. An import or assignment that renames either command
 * fails. IAM action names DeletePublicAccessBlock and
 * DeleteBucketPublicAccessBlock stay blocked in every policy. The
 * policy-vs-command check maps DeletePublicAccessBlockCommand to
 * s3:PutBucketPublicAccessBlock, the action AWS authorizes for that API.
 *
 * The xAI endpoint and the key and model env names may appear only in the
 * Grok client and its unit test.
 *
 * Tokens below are split so this file does not contain the token it searches for.
 */

export type SourceFile = {
  path: string;
  text: string;
};

export type FixFolder = {
  name: string;
  handlerText: string | null;
  policyText: string | null;
  metadataText: string | null;
  hasTest: boolean;
};

export type AllowEntry = {
  readonly action: string;
  readonly findingKey: string;
};

export type RegistryEntry = {
  readonly findingKey: string;
  readonly functionName: string;
};

export type AuditInput = {
  files: readonly SourceFile[];
  fixes: readonly FixFolder[];
  allowList: Readonly<Record<string, AllowEntry>>;
  registry: Readonly<Record<string, RegistryEntry>>;
  closeOnlyActions: readonly string[];
  xaiMarkers: readonly string[];
  grokClientPath: string;
  xaiAllowedPaths: readonly string[];
  /** When set, every fix folder must be listed in infra and the module must set a boundary. */
  terraform?: {
    mainText: string;
    moduleText: string;
  };
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
const COMMAND = /new\s+(?:[A-Za-z_$][\w$]*\s*\.\s*)?([A-Z][A-Za-z0-9]*)Command\b/g;

export function audit(input: AuditInput): AuditFailure[] {
  const failures: AuditFailure[] = [];

  for (const action of input.closeOnlyActions) {
    if (!isIamAction(action) || isBlocked(action)) {
      failures.push({
        path: 'src/guard/mutating-apis.ts',
        message: `close-only list contains a blocked action ${action}`,
      });
    }
  }

  scanSources(input, failures);
  scanDeletePublicAccessBlockSources(input.files, failures);

  const fixNames = new Set(input.fixes.map((fix) => fix.name));
  for (const name of Object.keys(input.allowList)) {
    if (!fixNames.has(name)) {
      failures.push({
        path: 'src/fixes/allow-list.ts',
        message: `allow-list entry ${name} has no fix folder`,
      });
    }
  }
  for (const name of Object.keys(input.registry)) {
    if (!fixNames.has(name)) {
      failures.push({
        path: 'src/fixes/registry.ts',
        message: `registry key ${name} has no fix folder`,
      });
    }
  }

  for (const fix of input.fixes) {
    scanFix(fix, input, failures);
  }

  if (input.terraform !== undefined) {
    scanTerraform(input.fixes, input.terraform, failures);
  }

  return failures;
}

function scanTerraform(
  fixes: readonly FixFolder[],
  terraform: { mainText: string; moduleText: string },
  failures: AuditFailure[],
): void {
  const listed = listedFixNames(terraform.mainText);
  if (listed === undefined) {
    failures.push({
      path: 'infra/main.tf',
      message: 'infra/main.tf is missing the fix_names list',
    });
  } else {
    const listedSet = new Set(listed);
    for (const fix of fixes) {
      if (!listedSet.has(fix.name)) {
        failures.push({
          path: 'infra/main.tf',
          message: `fix ${fix.name} has no Terraform entry`,
        });
      }
    }
    const folderNames = new Set(fixes.map((fix) => fix.name));
    for (const name of listed) {
      if (!folderNames.has(name)) {
        failures.push({
          path: 'infra/main.tf',
          message: `Terraform lists ${name} but that fix folder does not exist`,
        });
      }
    }
  }

  if (!/permissions_boundary\s*=\s*var\.permissions_boundary_arn/.test(terraform.moduleText)) {
    failures.push({
      path: 'infra/modules/fix/main.tf',
      message: 'fix module does not set permissions_boundary',
    });
  }
}

function listedFixNames(mainText: string): string[] | undefined {
  const match = /fix_names\s*=\s*toset\(\[([\s\S]*?)\]\)/.exec(mainText);
  const body = match?.[1];
  if (body === undefined) {
    return undefined;
  }
  return [...body.matchAll(/"([a-z0-9]+(?:-[a-z0-9]+)*)"/g)]
    .map((found) => found[1])
    .filter((name): name is string => name !== undefined);
}

function scanSources(input: AuditInput, failures: AuditFailure[]): void {
  for (const file of input.files) {
    if (!input.xaiAllowedPaths.includes(file.path)) {
      for (const marker of input.xaiMarkers) {
        if (marker.length > 0 && file.text.includes(marker)) {
          failures.push({
            path: file.path,
            message: `xAI call marker outside the Grok client: ${marker}`,
          });
        }
      }
    }

    if (!file.path.startsWith('src/')) {
      continue;
    }

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

    if (file.path !== input.grokClientPath && file.text.includes(EXTRACT_CALL)) {
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
  }
}

function scanFix(fix: FixFolder, input: AuditInput, failures: AuditFailure[]): void {
  const folder = `src/fixes/${fix.name}`;
  if (fix.handlerText === null) {
    failures.push({ path: folder, message: `fix ${fix.name} is missing handler.ts` });
  } else {
    scanDeletePublicAccessBlock(fix, failures);
  }
  if (fix.policyText === null) {
    failures.push({ path: folder, message: `fix ${fix.name} is missing policy.json` });
  }
  if (fix.metadataText === null) {
    failures.push({ path: folder, message: `fix ${fix.name} is missing fix.json` });
  }
  if (!fix.hasTest) {
    failures.push({ path: folder, message: `fix ${fix.name} is missing tests` });
  }

  const allowed = input.allowList[fix.name];
  if (allowed === undefined) {
    failures.push({ path: folder, message: `fix ${fix.name} is not on the allow-list` });
  }

  const registered = input.registry[fix.name];
  if (registered === undefined) {
    failures.push({ path: 'src/fixes/registry.ts', message: `registry is missing ${fix.name}` });
  } else if (registered.functionName !== `ag-fix-${fix.name}`) {
    failures.push({
      path: 'src/fixes/registry.ts',
      message: `registry function for ${fix.name} must be ag-fix-${fix.name}`,
    });
  }

  const metadata = parseMetadata(fix.metadataText);
  if (fix.metadataText !== null && metadata === undefined) {
    failures.push({ path: `${folder}/fix.json`, message: `fix ${fix.name} metadata is not the expected object` });
  }

  if (metadata !== undefined && allowed !== undefined) {
    if (metadata.name !== fix.name) {
      failures.push({ path: `${folder}/fix.json`, message: `fix ${fix.name} metadata name does not match the folder` });
    }
    if (metadata.action !== allowed.action) {
      failures.push({
        path: `${folder}/fix.json`,
        message: `fix ${fix.name} metadata action does not match the allow-list`,
      });
    }
    if (metadata.findingKey !== allowed.findingKey) {
      failures.push({
        path: `${folder}/fix.json`,
        message: `fix ${fix.name} finding key does not match the allow-list`,
      });
    }
    if (registered !== undefined && metadata.findingKey !== registered.findingKey) {
      failures.push({
        path: `${folder}/fix.json`,
        message: `fix ${fix.name} finding key does not match the registry`,
      });
    }
    if (!metadata.callsGrok && fix.handlerText !== null && fix.handlerText.includes(EXTRACT_CALL)) {
      failures.push({
        path: `${folder}/handler.ts`,
        message: `fix ${fix.name} calls Grok but fix.json says callsGrok is false`,
      });
    }
  }

  const policyActions = parsePolicy(
    fix.policyText,
    metadata,
    input.closeOnlyActions,
    `${folder}/policy.json`,
    failures,
  );
  if (fix.policyText !== null && policyActions === undefined) {
    return;
  }

  const actions = policyActions ?? [];
  const mutating = actions.filter((action) => isIamAction(action) && !isRead(action) && !isBlocked(action));
  if (fix.policyText !== null && mutating.length !== 1) {
    failures.push({
      path: `${folder}/policy.json`,
      message: `fix ${fix.name} has ${mutating.length} mutating actions`,
    });
  }
  if (allowed !== undefined && mutating.length === 1 && mutating[0] !== allowed.action) {
    failures.push({
      path: `${folder}/policy.json`,
      message: `fix ${fix.name} policy action does not match the allow-list`,
    });
  }

  if (fix.handlerText === null) {
    return;
  }

  const commands = [...fix.handlerText.matchAll(COMMAND)]
    .map((match) => match[1])
    .filter((name): name is string => name !== undefined);
  const closeCalls = commands.filter((name) => !isReadCommand(name));
  if (closeCalls.length !== 1) {
    failures.push({
      path: `${folder}/handler.ts`,
      message: `fix ${fix.name} has ${closeCalls.length} close calls`,
    });
  }

  for (const command of commands) {
    const listed = actions.some((action) => actionCoversCommand(action, command, fix));
    if (!listed) {
      failures.push({
        path: `${folder}/handler.ts`,
        message: `handler calls ${command} which policy.json does not list`,
      });
    }
  }

  for (const action of actions) {
    if (!isIamAction(action)) {
      continue;
    }
    const used = commands.some((command) => actionCoversCommand(action, command, fix));
    if (!used) {
      failures.push({
        path: `${folder}/policy.json`,
        message: `policy allows ${action} which the handler does not call`,
      });
    }
  }

  if (allowed !== undefined) {
    scanAutoRemediateTag(fix, failures);
    scanPublicTag(fix, failures);
  }
}

type Metadata = {
  name: string;
  findingKey: string;
  action: string;
  callsGrok: boolean;
  wildcardResourceJustification: string;
};

function parseMetadata(text: string | null): Metadata | undefined {
  if (text === null) {
    return undefined;
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (typeof value !== 'object' || value === null) {
    return undefined;
  }
  const record = value as Record<string, unknown>;
  if (typeof record.name !== 'string' || typeof record.findingKey !== 'string' || typeof record.action !== 'string') {
    return undefined;
  }
  if (typeof record.description !== 'string' || record.description.length === 0 || record.description.includes('\n')) {
    return undefined;
  }
  if (typeof record.callsGrok !== 'boolean') {
    return undefined;
  }
  const justification = record.wildcardResourceJustification;
  if (justification !== undefined && typeof justification !== 'string') {
    return undefined;
  }
  return {
    name: record.name,
    findingKey: record.findingKey,
    action: record.action,
    callsGrok: record.callsGrok,
    wildcardResourceJustification: typeof justification === 'string' ? justification.trim() : '',
  };
}

function parsePolicy(
  text: string | null,
  metadata: Metadata | undefined,
  closeOnlyActions: readonly string[],
  path: string,
  failures: AuditFailure[],
): string[] | undefined {
  if (text === null) {
    return undefined;
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    failures.push({ path, message: 'policy.json is not valid JSON' });
    return undefined;
  }
  if (typeof value !== 'object' || value === null) {
    failures.push({ path, message: 'policy.json is not an object' });
    return undefined;
  }
  const statements = (value as { Statement?: unknown }).Statement;
  if (!Array.isArray(statements)) {
    failures.push({ path, message: 'policy.json is missing Statement' });
    return undefined;
  }

  const actions: string[] = [];
  for (const statement of statements) {
    if (typeof statement !== 'object' || statement === null) {
      failures.push({ path, message: 'policy statement is not an object' });
      continue;
    }
    const record = statement as Record<string, unknown>;
    if ('NotAction' in record) {
      failures.push({ path, message: 'policy statement uses NotAction' });
      continue;
    }
    if (record.Effect !== 'Allow') {
      failures.push({ path, message: 'policy statement Effect must be Allow' });
      continue;
    }
    const statementActions = readActions(record.Action);
    if (statementActions === undefined) {
      failures.push({ path, message: 'policy statement Action is missing' });
      continue;
    }
    const resources = readResources(record.Resource);
    if (resources === undefined) {
      failures.push({ path, message: 'policy statement Resource is missing' });
      continue;
    }

    let mutating = false;
    for (const action of statementActions) {
      actions.push(action);
      if (!isIamAction(action) || action.includes('*')) {
        failures.push({ path, message: `wildcard action ${action}` });
        continue;
      }
      if (isBlocked(action)) {
        failures.push({ path, message: `blocked action ${action}` });
        continue;
      }
      if (!isRead(action)) {
        mutating = true;
        if (!closeOnlyActions.includes(action)) {
          failures.push({ path, message: `mutating action ${action} is not on the close-only list` });
        }
      }
    }

    if (mutating && resources.some((resource) => resource === '*')) {
      const justification = metadata?.wildcardResourceJustification ?? '';
      if (justification.length === 0) {
        failures.push({
          path,
          message: 'mutating action uses Resource * without justification',
        });
      }
    }
  }

  return actions;
}

function readActions(value: unknown): string[] | undefined {
  if (typeof value === 'string') {
    return [value];
  }
  if (!Array.isArray(value) || value.length === 0 || value.some((item) => typeof item !== 'string')) {
    return undefined;
  }
  return value as string[];
}

function readResources(value: unknown): string[] | undefined {
  if (typeof value === 'string') {
    return [value];
  }
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    return undefined;
  }
  return value as string[];
}

function isIamAction(action: string): boolean {
  return /^[a-z0-9]+:[A-Za-z0-9]+$/.test(action);
}

function actionName(action: string): string {
  const parts = action.split(':');
  return parts[1] ?? '';
}

const AUTO_REMEDIATE_TAG_KEY_DECL = "const AUTO_REMEDIATE_TAG_KEY = 'auto-remediate'";
const AUTO_REMEDIATE_TAG_VALUE_DECL = "const AUTO_REMEDIATE_TAG_VALUE = 'true'";

/**
 * Allow-listed handlers must declare the tag constants and call
 * hasAutoRemediateTag( before the mutating command. A function declaration
 * of that name does not count as the call.
 */
function scanAutoRemediateTag(fix: FixFolder, failures: AuditFailure[]): void {
  const text = fix.handlerText;
  if (text === null) {
    return;
  }
  const path = `src/fixes/${fix.name}/handler.ts`;
  if (!text.includes(AUTO_REMEDIATE_TAG_KEY_DECL)) {
    failures.push({
      path,
      message: `fix ${fix.name} does not declare const AUTO_REMEDIATE_TAG_KEY = 'auto-remediate'`,
    });
  }
  if (!text.includes(AUTO_REMEDIATE_TAG_VALUE_DECL)) {
    failures.push({
      path,
      message: `fix ${fix.name} does not declare const AUTO_REMEDIATE_TAG_VALUE = 'true'`,
    });
  }

  const mutatingAt = firstMutatingCommandIndex(text);
  if (mutatingAt === undefined) {
    return;
  }
  const callAt = firstTagCallIndex(text);
  if (callAt === undefined) {
    failures.push({
      path,
      message: `fix ${fix.name} does not call hasAutoRemediateTag( before its mutating send`,
    });
    return;
  }
  if (callAt > mutatingAt) {
    failures.push({
      path,
      message: `fix ${fix.name} calls hasAutoRemediateTag( after its mutating send`,
    });
  }
}

function firstMutatingCommandIndex(text: string): number | undefined {
  for (const match of text.matchAll(COMMAND)) {
    const name = match[1];
    if (name === undefined || isReadCommand(name) || match.index === undefined) {
      continue;
    }
    return match.index;
  }
  return undefined;
}

/** The first hasAutoRemediateTag( that is a call, not the function declaration. */
function firstTagCallIndex(text: string): number | undefined {
  const needle = 'hasAutoRemediateTag';
  let from = 0;
  while (from < text.length) {
    const index = text.indexOf(needle, from);
    if (index === -1) {
      return undefined;
    }
    const after = text.slice(index + needle.length);
    if (!/^\s*\(/.test(after)) {
      from = index + needle.length;
      continue;
    }
    if (/(?:function\s+)$/.test(text.slice(0, index))) {
      from = index + needle.length;
      continue;
    }
    return index;
  }
  return undefined;
}

const PUBLIC_TAG_KEY_DECL = "const PUBLIC_TAG_KEY = 'public'";
const PUBLIC_TAG_VALUE_DECL = "const PUBLIC_TAG_VALUE = 'true'";
const PUBLIC_TAG_PRESENT = /if\s*\(\s*!\s*hasPublicTag\s*\(/;
const PUBLIC_TAG_ABSENT = /if\s*\(\s*hasPublicTag\s*\(/;

/**
 * remove-bucket-public-access-block must refuse unless public=true
 * is present. restore-bucket-public-access-block must refuse when that tag
 * is present. The if form has to appear before the mutating command so the
 * guard can see which way the check goes.
 */
function scanPublicTag(fix: FixFolder, failures: AuditFailure[]): void {
  const mode = publicTagMode(fix.name);
  if (mode === undefined) {
    return;
  }
  const text = fix.handlerText;
  if (text === null) {
    return;
  }
  const path = `src/fixes/${fix.name}/handler.ts`;
  if (!text.includes(PUBLIC_TAG_KEY_DECL)) {
    failures.push({
      path,
      message: `fix ${fix.name} does not declare const PUBLIC_TAG_KEY = 'public'`,
    });
  }
  if (!text.includes(PUBLIC_TAG_VALUE_DECL)) {
    failures.push({
      path,
      message: `fix ${fix.name} does not declare const PUBLIC_TAG_VALUE = 'true'`,
    });
  }

  const mutatingAt = firstMutatingCommandIndex(text);
  if (mutatingAt === undefined) {
    return;
  }
  const before = text.slice(0, mutatingAt);
  const after = text.slice(mutatingAt);
  const matchedBefore = mode === 'present' ? PUBLIC_TAG_PRESENT.test(before) : PUBLIC_TAG_ABSENT.test(before);
  if (matchedBefore) {
    return;
  }
  const matchedAfter = mode === 'present' ? PUBLIC_TAG_PRESENT.test(after) : PUBLIC_TAG_ABSENT.test(after);
  if (matchedAfter) {
    failures.push({
      path,
      message: `fix ${fix.name} checks public=true after its mutating send`,
    });
    return;
  }
  const requirement = mode === 'present' ? 'present' : 'absent';
  failures.push({
    path,
    message: `fix ${fix.name} does not require public=true to be ${requirement} before its mutating send`,
  });
}

function publicTagMode(name: string): 'present' | 'absent' | undefined {
  if (name === 'remove-bucket-public-access-block') {
    return 'present';
  }
  if (name === 'restore-bucket-public-access-block') {
    return 'absent';
  }
  return undefined;
}

function isRead(action: string): boolean {
  return isReadCommand(actionName(action));
}

function isReadCommand(name: string): boolean {
  return name.startsWith('Describe') || name.startsWith('List') || name.startsWith('Get');
}

/**
 * Opens, deletes public access, IAM, or a policy write.
 * DeletePublicAccessBlock and DeleteBucketPublicAccessBlock never pass in a
 * policy. The SDK command exception does not add those IAM names.
 *
 * iam:PutUserPolicy is the one mutating exception. contain-iam-user uses it
 * to attach a fixed deny-all inline policy. The same fix's reads are the
 * only other iam strings that pass: GetUser, ListUserTags, GetUserPolicy,
 * ListAttachedUserPolicies, and ListGroupsForUser. Every other iam action
 * stays blocked. Every other Put*Policy action stays blocked.
 */
const CONTAINMENT_IAM_READS = new Set([
  'iam:GetUser',
  'iam:ListUserTags',
  'iam:GetUserPolicy',
  'iam:ListAttachedUserPolicies',
  'iam:ListGroupsForUser',
]);

function isBlocked(action: string): boolean {
  if (action === 'iam:PutUserPolicy') {
    return false;
  }
  if (CONTAINMENT_IAM_READS.has(action)) {
    return false;
  }
  if (action.startsWith('iam:')) {
    return true;
  }
  const name = actionName(action);
  if (name.startsWith('Authorize')) {
    return true;
  }
  if (name === 'DeletePublicAccessBlock' || name === 'DeleteBucketPublicAccessBlock') {
    return true;
  }
  if (/^Delete.*PublicAccessBlock$/.test(name)) {
    return true;
  }
  if (/^Put.*Policy$/.test(name)) {
    return true;
  }
  return false;
}

const DELETE_PUBLIC_ACCESS_BLOCK_COMMAND = 'DeletePublicAccessBlockCommand';
const DELETE_BUCKET_PUBLIC_ACCESS_BLOCK_COMMAND = 'DeleteBucketPublicAccessBlockCommand';
const REMOVE_BUCKET_PUBLIC_ACCESS_BLOCK_HANDLER = 'src/fixes/remove-bucket-public-access-block/handler.ts';

// AWS authorizes bucket DeletePublicAccessBlock under s3:PutBucketPublicAccessBlock.
// The policy-vs-command check uses this map. The import keeps its real name.
const DELETE_COMMAND_TO_IAM_ACTION: Readonly<Record<string, string>> = {
  DeletePublicAccessBlockCommand: 's3:PutBucketPublicAccessBlock',
  DeleteBucketPublicAccessBlockCommand: 's3:PutBucketPublicAccessBlock',
};

const DELETE_COMMAND_USE =
  /new\s+(?:[A-Za-z_$][\w$]*\s*\.\s*)?(Delete(?:Bucket)?PublicAccessBlockCommand)\b/g;
const DELETE_IMPORT_ALIAS = /Delete(?:Bucket)?PublicAccessBlockCommand\s+as\s+([A-Za-z0-9_]+)/g;
const DELETE_ASSIGN_ALIAS =
  /(?:const|let|var)\s+([A-Za-z0-9_]+)\s*=\s*(Delete(?:Bucket)?PublicAccessBlockCommand)\b/g;

type DeleteTagGate = {
  label: string;
  keyDecl: string;
  valueDecl: string;
  call: RegExp;
};

const DELETE_TAG_GATES: readonly DeleteTagGate[] = [
  {
    label: 'public=true',
    keyDecl: "const PUBLIC_TAG_KEY = 'public'",
    valueDecl: "const PUBLIC_TAG_VALUE = 'true'",
    call: /if\s*\(\s*!\s*hasPublicTag\s*\(/,
  },
  {
    label: 'auto-remediate=true',
    keyDecl: "const AUTO_REMEDIATE_TAG_KEY = 'auto-remediate'",
    valueDecl: "const AUTO_REMEDIATE_TAG_VALUE = 'true'",
    call: /if\s*\(\s*!\s*hasAutoRemediateTag\s*\(/,
  },
  {
    label: 'purpose=ag-demo-synthetic',
    keyDecl: "const PURPOSE_TAG_KEY = 'purpose'",
    valueDecl: "const PURPOSE_TAG_VALUE = 'ag-demo-synthetic'",
    call: /if\s*\(\s*!\s*hasDemoPurpose\s*\(/,
  },
];

function actionCoversCommand(action: string, command: string, fix: FixFolder): boolean {
  if (actionName(action) === command) {
    return true;
  }
  const mapped = DELETE_COMMAND_TO_IAM_ACTION[`${command}Command`];
  return mapped === action && deleteExceptionApplies(fix);
}

function deleteExceptionApplies(fix: FixFolder): boolean {
  const text = fix.handlerText;
  if (text === null || fix.name !== 'remove-bucket-public-access-block') {
    return false;
  }
  if (aliasedDeletePublicAccessBlocks(text).length > 0) {
    return false;
  }
  return deleteTagProblems(text).length === 0 && deleteCommandUses(text).length > 0;
}

/**
 * The delete command is allowed only in the remove handler, and only after
 * the three exact tag checks. A renamed import or assignment fails everywhere.
 */
function scanDeletePublicAccessBlock(fix: FixFolder, failures: AuditFailure[]): void {
  const text = fix.handlerText;
  if (text === null) {
    return;
  }
  const path = `src/fixes/${fix.name}/handler.ts`;
  for (const alias of aliasedDeletePublicAccessBlocks(text)) {
    failures.push({
      path,
      message: `handler aliases ${alias}`,
    });
  }

  const uses = deleteCommandUses(text);
  if (uses.length === 0) {
    return;
  }
  if (path !== REMOVE_BUCKET_PUBLIC_ACCESS_BLOCK_HANDLER) {
    failures.push({
      path,
      message: `${DELETE_PUBLIC_ACCESS_BLOCK_COMMAND} is only allowed in ${REMOVE_BUCKET_PUBLIC_ACCESS_BLOCK_HANDLER}`,
    });
    return;
  }
  for (const problem of deleteTagProblems(text)) {
    failures.push({ path, message: problem });
  }
}

function scanDeletePublicAccessBlockSources(files: readonly SourceFile[], failures: AuditFailure[]): void {
  for (const file of files) {
    if (!file.path.startsWith('src/') || file.path === REMOVE_BUCKET_PUBLIC_ACCESS_BLOCK_HANDLER) {
      continue;
    }
    for (const alias of aliasedDeletePublicAccessBlocks(file.text)) {
      failures.push({
        path: file.path,
        message: `handler aliases ${alias}`,
      });
    }
    if (deleteCommandUses(file.text).length > 0) {
      failures.push({
        path: file.path,
        message: `${DELETE_PUBLIC_ACCESS_BLOCK_COMMAND} is only allowed in ${REMOVE_BUCKET_PUBLIC_ACCESS_BLOCK_HANDLER}`,
      });
    }
  }
}

function deleteCommandUses(text: string): string[] {
  const names = new Set<string>();
  for (const match of text.matchAll(new RegExp(DELETE_COMMAND_USE.source, 'g'))) {
    const name = match[1];
    if (name !== undefined) {
      names.add(name);
    }
  }
  return [...names];
}

function aliasedDeletePublicAccessBlocks(text: string): string[] {
  const aliases: string[] = [];
  for (const match of text.matchAll(new RegExp(DELETE_IMPORT_ALIAS.source, 'g'))) {
    const alias = match[1];
    const original = match[0].startsWith(DELETE_BUCKET_PUBLIC_ACCESS_BLOCK_COMMAND)
      ? DELETE_BUCKET_PUBLIC_ACCESS_BLOCK_COMMAND
      : DELETE_PUBLIC_ACCESS_BLOCK_COMMAND;
    if (alias !== undefined && alias !== original) {
      aliases.push(`${original} as ${alias}`);
    }
  }
  for (const match of text.matchAll(new RegExp(DELETE_ASSIGN_ALIAS.source, 'g'))) {
    const alias = match[1];
    const original = match[2];
    if (alias !== undefined && original !== undefined && alias !== original) {
      aliases.push(`${original} as ${alias}`);
    }
  }
  return aliases;
}

function deleteTagProblems(text: string): string[] {
  const problems: string[] = [];
  const sendAt = firstDeleteCommandIndex(text);
  for (const gate of DELETE_TAG_GATES) {
    if (!text.includes(gate.keyDecl) || !text.includes(gate.valueDecl)) {
      problems.push(
        `${DELETE_PUBLIC_ACCESS_BLOCK_COMMAND} is missing the ${gate.label} check before the send`,
      );
      continue;
    }
    if (sendAt === undefined) {
      continue;
    }
    const before = text.slice(0, sendAt);
    const after = text.slice(sendAt);
    if (gate.call.test(before)) {
      continue;
    }
    if (gate.call.test(after)) {
      problems.push(`${DELETE_PUBLIC_ACCESS_BLOCK_COMMAND} checks ${gate.label} after the send`);
      continue;
    }
    problems.push(`${DELETE_PUBLIC_ACCESS_BLOCK_COMMAND} is missing the ${gate.label} check before the send`);
  }
  return problems;
}

function firstDeleteCommandIndex(text: string): number | undefined {
  const match = new RegExp(DELETE_COMMAND_USE.source).exec(text);
  return match?.index;
}
