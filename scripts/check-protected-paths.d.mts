export function isProtectedPath(file: string): boolean;
export function findProtectedPaths(files: readonly string[]): string[];
export function evaluate(
  files: readonly string[],
  hasGuardLabel: boolean,
): { ok: boolean; hits: string[] };
export function changedFilesFromEnv(env?: NodeJS.ProcessEnv): string[];
