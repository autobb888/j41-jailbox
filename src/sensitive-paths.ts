/**
 * Sensitive-write classification.
 *
 * The jailbox confines an agent's writes to the mounted repo — it CANNOT write
 * outside it (see resolveSafe + escape-confinement tests). But "the repo"
 * includes files that execute on the BUYER's host later, when the buyer uses
 * the repo normally: git hooks fire on commit/checkout, package.json scripts run
 * on `npm install`, Makefiles/CI configs/Dockerfiles run on build, `.envrc` runs
 * under direnv on `cd`. A hired agent could plant a payload in one of these and
 * it would execute outside the sandbox at a later time.
 *
 * This module flags such writes so the supervisor prompt (and the live feed in
 * standard mode) can call them out for closer human review. It is NOT a block —
 * confinement + SovGuard content scanning + per-write approval are the controls;
 * this is the "look harder at THIS one" signal.
 */

export interface SensitiveClassification {
  sensitive: boolean;
  category?: string;
  reason?: string;
}

/** Split a relative path into clean posix segments (handles ./ and trailing /). */
function segments(relPath: string): string[] {
  return relPath.split(/[\\/]+/).filter((s) => s && s !== '.');
}

interface Rule {
  category: string;
  reason: string;
  test: (segs: string[], base: string) => boolean;
}

const RULES: Rule[] = [
  {
    category: 'git-hook',
    reason: 'Git hook — executes on git operations (commit/checkout/push) on your host',
    test: (segs) => {
      const i = segs.indexOf('.git');
      return i !== -1 && segs[i + 1] === 'hooks' && segs.length > i + 2;
    },
  },
  {
    category: 'git-config',
    reason: '.git/config — can set core.hooksPath / aliases / core.fsmonitor that execute commands',
    test: (segs, base) => segs.includes('.git') && base === 'config',
  },
  {
    category: 'git-internal',
    reason: 'Write inside .git/ — can alter how the repository executes',
    test: (segs) => segs.includes('.git'),
  },
  {
    category: 'npm-scripts',
    reason: 'package.json — npm lifecycle scripts (preinstall/postinstall/prepare) run on install',
    test: (_segs, base) => base === 'package.json',
  },
  {
    category: 'npm-config',
    reason: '.npmrc — can redirect the registry or inject install behaviour',
    test: (_segs, base) => base === '.npmrc',
  },
  {
    category: 'shell-rc',
    reason: 'Shell/direnv rc file — executes when you open a shell or cd into the repo',
    test: (_segs, base) =>
      ['.bashrc', '.zshrc', '.profile', '.bash_profile', '.zprofile', '.envrc', '.bash_aliases'].includes(base),
  },
  {
    category: 'shell-script',
    reason: 'Shell script — executes if you (or a tool) run it',
    test: (_segs, base) => /\.(sh|bash|zsh)$/.test(base),
  },
  {
    category: 'make',
    reason: 'Makefile — recipes execute on `make`',
    test: (_segs, base) => ['makefile', 'gnumakefile'].includes(base.toLowerCase()),
  },
  {
    category: 'ci-workflow',
    reason: 'CI workflow — executes in your CI on push',
    test: (segs) => segs.includes('.github') && segs.includes('workflows'),
  },
  {
    category: 'ci',
    reason: 'CI pipeline config — executes in CI',
    test: (segs, base) =>
      segs.includes('.circleci') ||
      ['.gitlab-ci.yml', 'azure-pipelines.yml', 'jenkinsfile', '.travis.yml', 'bitbucket-pipelines.yml'].includes(
        base.toLowerCase(),
      ),
  },
  {
    category: 'docker-build',
    reason: 'Docker build file — executes on image build',
    test: (_segs, base) => {
      const b = base.toLowerCase();
      return b === 'dockerfile' || b.startsWith('dockerfile.') || /^docker-compose.*\.ya?ml$/.test(b);
    },
  },
  {
    category: 'build-script',
    reason: 'Build script — executes during the package build/install',
    test: (_segs, base) => ['setup.py', 'build.rs', 'binding.gyp', 'conanfile.py'].includes(base),
  },
  {
    category: 'pre-commit',
    reason: 'pre-commit config — executes hooks on commit',
    test: (_segs, base) => base === '.pre-commit-config.yaml',
  },
  {
    category: 'editor-task',
    reason: 'Editor task/launch config — can auto-run commands when the repo is opened',
    test: (segs, base) => segs.includes('.vscode') && ['tasks.json', 'launch.json'].includes(base),
  },
];

/**
 * Classify whether a write to `relPath` lands on a file that can execute on the
 * host later. Returns the first matching category.
 */
export function classifySensitiveWrite(relPath: string): SensitiveClassification {
  const segs = segments(relPath);
  if (segs.length === 0) return { sensitive: false };
  const base = segs[segs.length - 1];
  for (const rule of RULES) {
    if (rule.test(segs, base)) {
      return { sensitive: true, category: rule.category, reason: rule.reason };
    }
  }
  return { sensitive: false };
}
