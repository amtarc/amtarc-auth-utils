# Contributing to amtarc-auth-utils

Thank you for your interest in contributing to amtarc-auth-utils! We welcome contributions from the community.

## Getting Started

### Prerequisites

- Node.js 18 or higher
- pnpm 9 or higher
- Git

### Setup

1. Fork the repository on GitHub
2. Clone your fork locally:

```bash
git clone https://github.com/amtarc/amtarc-auth-utils.git
cd amtarc-auth-utils
```

3. Install dependencies:

```bash
pnpm install
```

4. Build all packages:

```bash
pnpm build
```

5. Run tests:

```bash
pnpm test
```

## Development Workflow

### Creating a Branch

```bash
git checkout -b feat/my-new-feature
# or
git checkout -b fix/issue-123
```

### Making Changes

1. Make your changes in the appropriate package(s)
2. Add tests for your changes
3. Update documentation if needed
4. Ensure all tests pass: `pnpm test`
5. Ensure linting passes: `pnpm lint`
6. Ensure type checking passes: `pnpm typecheck`

### Commit Guidelines

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(core): add new session fingerprinting feature
fix(security): resolve CSRF token validation issue
docs(guide): update installation instructions
test(authorization): add tests for RBAC
chore(deps): update dependencies
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code changes that neither fix bugs nor add features
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Maintenance tasks
- `ci`: CI/CD changes

**Scopes:**
- `core`, `security`, `authorization`, `tokens`, `multi-tenancy`, `audit`, `testing`, `observability`
- `adapters` for adapter packages
- `docs` for documentation
- `deps` for dependency updates

### Running Tests

```bash
# Run all tests
pnpm test

# Run tests in watch mode
pnpm test:watch

# Run tests with coverage
pnpm test:coverage

# Run tests for specific package
cd packages/core
pnpm test
```

### Code Quality

Before submitting a PR, ensure:

```bash
# Linting passes
pnpm lint

# Type checking passes
pnpm typecheck

# All tests pass
pnpm test:run

# Build succeeds
pnpm build
```

### Pull Request Process

1. Update the README.md or documentation with details of changes if applicable
2. Add tests for your changes
3. Ensure all checks pass (CI will run automatically)
4. Create a changeset describing your changes:

```bash
pnpm changeset
```

Follow the prompts to describe your changes. This will be used for automatic versioning and changelog generation.

5. Push your branch and create a Pull Request on GitHub
6. Wait for review and address any feedback


## Writing Tests

- Place test files next to the code they test: `module.test.ts`
- Use descriptive test names
- Follow the Arrange-Act-Assert pattern
- Aim for >90% code coverage

Example:

```typescript
import { describe, it, expect } from 'vitest';
import { createSession } from './create-session';

describe('createSession', () => {
  it('should create a session with default options', () => {
    // Arrange
    const userId = 'user-123';
    
    // Act
    const session = createSession(userId);
    
    // Assert
    expect(session.id).toBeDefined();
    expect(session.userId).toBe(userId);
  });
});
```

## Documentation

- Update documentation for any user-facing changes
- Add JSDoc comments for all public APIs
- Include code examples in documentation
- Keep README files up to date

## Getting Help

- Create an issue for bugs or feature requests
- Join our Discord community (link coming soon)
- Ask questions in GitHub Discussions

## Code of Conduct

Please be respectful and constructive in all interactions. We're building a welcoming community for everyone.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
