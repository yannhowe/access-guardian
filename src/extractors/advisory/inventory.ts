/**
 * Compare a verified advisory with the service inventory.
 * This file does not call Grok. It does not decide that a version is safe
 * when the version string cannot be read.
 */
import { readFileSync } from 'node:fs';
import { PACKAGE_RE, VERSION_RE } from './patterns.js';
import { canonicalAffectedRange, versionInsideRanges } from './ranges.js';
import type { VerifiedAdvisory } from './types.js';

export type ServiceExposure = {
  name: string;
  affected: boolean;
  installedVersion: string | null;
  reason: 'not_installed' | 'in_range' | 'outside_range' | 'fixed_version';
};

export type ServiceInventory = {
  services: InventoryService[];
};

type InventoryService = {
  name: string;
  ownerTeam: string;
  environment: string;
  dependencies: InventoryDependency[];
};

type InventoryDependency = {
  name: string;
  version: string;
};

export type CompareResult =
  | { ok: true; packageName: string; services: ServiceExposure[] }
  | { ok: false; reason: 'invalid_facts' | 'invalid_inventory' };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseDependency(value: unknown): InventoryDependency | undefined {
  if (!isRecord(value)) {
    return undefined;
  }
  if (typeof value.name !== 'string' || value.name.length === 0 || value.name.length > 124) {
    return undefined;
  }
  if (typeof value.version !== 'string' || value.version.length === 0 || value.version.length > 80) {
    return undefined;
  }
  return { name: value.name, version: value.version };
}

function parseService(value: unknown): InventoryService | undefined {
  if (!isRecord(value)) {
    return undefined;
  }
  if (typeof value.name !== 'string' || value.name.length === 0 || value.name.length > 80) {
    return undefined;
  }
  if (typeof value.ownerTeam !== 'string' || value.ownerTeam.length === 0 || value.ownerTeam.length > 80) {
    return undefined;
  }
  if (typeof value.environment !== 'string' || value.environment.length === 0 || value.environment.length > 80) {
    return undefined;
  }
  if (!Array.isArray(value.dependencies)) {
    return undefined;
  }

  const dependencies: InventoryDependency[] = [];
  for (const entry of value.dependencies) {
    const dependency = parseDependency(entry);
    if (dependency === undefined) {
      return undefined;
    }
    dependencies.push(dependency);
  }

  return {
    name: value.name,
    ownerTeam: value.ownerTeam,
    environment: value.environment,
    dependencies,
  };
}

export function parseInventory(value: unknown): ServiceInventory | undefined {
  if (!isRecord(value) || !Array.isArray(value.services)) {
    return undefined;
  }

  const services: InventoryService[] = [];
  for (const entry of value.services) {
    const service = parseService(entry);
    if (service === undefined) {
      return undefined;
    }
    services.push(service);
  }
  return { services };
}

/** Read `inventory/services.json`. A bad file is `invalid_inventory`, not an empty report. */
export function loadServiceInventory(
  filePath: string,
): { ok: true; inventory: ServiceInventory } | { ok: false; reason: 'invalid_inventory' } {
  let text: string;
  try {
    text = readFileSync(filePath, 'utf8');
  } catch {
    return { ok: false, reason: 'invalid_inventory' };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ok: false, reason: 'invalid_inventory' };
  }

  const inventory = parseInventory(parsed);
  if (inventory === undefined) {
    return { ok: false, reason: 'invalid_inventory' };
  }
  return { ok: true, inventory };
}

function advisoryUsable(advisory: VerifiedAdvisory): boolean {
  if (!PACKAGE_RE.test(advisory.packageName) || !VERSION_RE.test(advisory.fixedVersion)) {
    return false;
  }
  return canonicalAffectedRange(advisory.affectedRanges) !== undefined;
}

function classify(service: InventoryService, advisory: VerifiedAdvisory): ServiceExposure | undefined {
  const installed = service.dependencies
    .filter((dependency) => dependency.name === advisory.packageName)
    .map((dependency) => dependency.version);

  if (installed.length === 0) {
    return {
      name: service.name,
      affected: false,
      installedVersion: null,
      reason: 'not_installed',
    };
  }

  let affectedVersion: string | undefined;
  let fixedInstalled: string | undefined;
  let outsideVersion: string | undefined;

  for (const version of installed) {
    if (version === advisory.fixedVersion) {
      if (VERSION_RE.test(version) === false) {
        return undefined;
      }
      fixedInstalled ??= version;
      continue;
    }

    const inside = versionInsideRanges(version, advisory.affectedRanges);
    if (inside === undefined) {
      return undefined;
    }
    if (inside) {
      affectedVersion ??= version;
    } else {
      outsideVersion ??= version;
    }
  }

  if (affectedVersion !== undefined) {
    return {
      name: service.name,
      affected: true,
      installedVersion: affectedVersion,
      reason: 'in_range',
    };
  }
  if (fixedInstalled !== undefined) {
    return {
      name: service.name,
      affected: false,
      installedVersion: fixedInstalled,
      reason: 'fixed_version',
    };
  }
  return {
    name: service.name,
    affected: false,
    installedVersion: outsideVersion ?? null,
    reason: 'outside_range',
  };
}

/**
 * Report every service.
 * A service that does not install the package is not affected.
 * The fixed version is not affected. A version that cannot be compared fails the report.
 */
export function compareInventory(advisory: VerifiedAdvisory, inventory: unknown): CompareResult {
  if (!advisoryUsable(advisory)) {
    return { ok: false, reason: 'invalid_facts' };
  }

  const parsed = parseInventory(inventory);
  if (parsed === undefined) {
    return { ok: false, reason: 'invalid_inventory' };
  }

  const services: ServiceExposure[] = [];
  for (const service of parsed.services) {
    const exposure = classify(service, advisory);
    if (exposure === undefined) {
      return { ok: false, reason: 'invalid_inventory' };
    }
    services.push(exposure);
  }

  return { ok: true, packageName: advisory.packageName, services };
}
