// Decides whether a Dependabot PR may be auto-merged. Reads the JSON that
// dependabot/fetch-metadata exposes as `updated-dependencies-json` from the DEPS
// environment variable. Exit 0 means eligible, anything else means leave it for a
// person. Every dependency in the PR must qualify, so one major bump in a group
// blocks the whole group.
//
// Eligible:
//   Go modules: patch and minor
//   GitHub Actions from the actions/ org: patch, minor and major
// Everything else (other ecosystems, other action owners, other majors,
// missing or unparseable metadata) waits for a human.

const SEMVER_SAFE = new Set(['version-update:semver-patch', 'version-update:semver-minor']);
const SEMVER_ECOSYSTEMS = new Set(['go_modules']);

export function eligible(dep) {
  if (!dep || typeof dep !== 'object') return false;
  const { packageEcosystem: eco, dependencyName: name, updateType: type } = dep;
  if (SEMVER_ECOSYSTEMS.has(eco)) return SEMVER_SAFE.has(type);
  if (eco === 'github_actions') return typeof name === 'string' && name.startsWith('actions/');
  return false;
}

export function allEligible(deps) {
  return Array.isArray(deps) && deps.length > 0 && deps.every(eligible);
}

function main() {
  let deps;
  try {
    deps = JSON.parse(process.env.DEPS ?? '');
  } catch {
    console.error('automerge: DEPS is missing or not JSON, leaving the PR for a person');
    return 1;
  }
  if (!allEligible(deps)) {
    console.error('automerge: not every dependency qualifies, leaving the PR for a person');
    return 1;
  }
  console.log(`automerge: ${deps.length} dependency update(s) qualify`);
  return 0;
}

process.exitCode = main();
