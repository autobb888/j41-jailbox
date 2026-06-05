import { describe, it, expect } from 'vitest';
import { classifySensitiveWrite } from '../src/sensitive-paths.js';

describe('classifySensitiveWrite — flags in-repo files that execute on the host', () => {
  const sensitive: Array<[string, string]> = [
    ['.git/hooks/pre-commit', 'git-hook'],
    ['.git/hooks/post-checkout', 'git-hook'],
    ['nested/.git/hooks/pre-push', 'git-hook'],
    ['.git/config', 'git-config'],
    ['.git/anything-else', 'git-internal'],
    ['package.json', 'npm-scripts'],
    ['packages/sub/package.json', 'npm-scripts'],
    ['.npmrc', 'npm-config'],
    ['.envrc', 'shell-rc'],
    ['.bashrc', 'shell-rc'],
    ['scripts/deploy.sh', 'shell-script'],
    ['Makefile', 'make'],
    ['GNUmakefile', 'make'],
    ['.github/workflows/ci.yml', 'ci-workflow'],
    ['.circleci/config.yml', 'ci'],
    ['Jenkinsfile', 'ci'],
    ['.gitlab-ci.yml', 'ci'],
    ['Dockerfile', 'docker-build'],
    ['Dockerfile.prod', 'docker-build'],
    ['docker-compose.yml', 'docker-build'],
    ['setup.py', 'build-script'],
    ['build.rs', 'build-script'],
    ['.pre-commit-config.yaml', 'pre-commit'],
    ['.vscode/tasks.json', 'editor-task'],
  ];

  for (const [path, category] of sensitive) {
    it(`flags ${path} as ${category}`, () => {
      const r = classifySensitiveWrite(path);
      expect(r.sensitive).toBe(true);
      expect(r.category).toBe(category);
      expect(r.reason).toBeTruthy();
    });
  }

  const benign = [
    'src/app.ts',
    'README.md',
    'docs/guide.md',
    'src/components/Button.tsx',
    'assets/logo.png',
    'data/users.json', // a plain json, not package.json
    'test/fixtures/sample.txt',
  ];
  for (const path of benign) {
    it(`does NOT flag ${path}`, () => {
      expect(classifySensitiveWrite(path).sensitive).toBe(false);
    });
  }

  it('handles ./ prefixes and backslashes', () => {
    expect(classifySensitiveWrite('./.git/hooks/pre-commit').category).toBe('git-hook');
    expect(classifySensitiveWrite('.github\\workflows\\ci.yml').category).toBe('ci-workflow');
  });
});
