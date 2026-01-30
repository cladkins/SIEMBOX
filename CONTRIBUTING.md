# Contributing to SIEMBox

Thank you for your interest in contributing to SIEMBox! This document provides guidelines for contributing to the project.

## Development Workflow

### Branches

- `main` - All development happens here

### Getting Started

1. Fork the repository (if external contributor)
2. Clone your fork or the main repository
3. Create a new feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

### Development Setup

**Prerequisites:**
- Node.js 18+
- Docker and Docker Compose
- PostgreSQL 15+ (if running locally without Docker)

**Backend Setup:**
```bash
cd backend
npm install
cp ../.env.example .env
# Edit .env with your local settings
npm run migrate
npm run dev
```

**Frontend Setup:**
```bash
cd frontend
npm install
npm run dev
```

### Code Style

- **TypeScript**: Use TypeScript for all new code
- **Linting**: Run `npm run lint` before committing
- **Formatting**: Run `npm run format` to format code with Prettier
- **Naming**: Use camelCase for variables/functions, PascalCase for classes/components

### Commit Messages

Follow conventional commit format:
```
type(scope): description

[optional body]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

Examples:
```
feat(parser): add support for Windows Event Logs
fix(rules): correct regex pattern for SSH brute force detection
docs(readme): update installation instructions
```

## Adding New Features

### Adding a New Parser

1. Add parser definition to `backend/migrations/002_seed_data.sql`
2. Test the parser with sample logs
3. Update documentation

### Adding a New Detection Rule

1. Create rule YAML in `backend/migrations/002_seed_data.sql`
2. Test rule against sample logs
3. Document the rule's purpose and triggers

### Adding API Endpoints

1. Create route in `backend/src/routes/`
2. Add business logic in `backend/src/services/`
3. Update API documentation
4. Add frontend integration in `frontend/src/services/api.ts`

### Adding Frontend Components

1. Create component in `frontend/src/components/`
2. Use Element Plus components for consistency
3. Add TypeScript types
4. Follow existing component patterns

## Testing

### Backend Testing

```bash
cd backend
npm test
```

### Frontend Testing

```bash
cd frontend
npm test
```

### Integration Testing

Test the full stack with Docker Compose:
```bash
docker-compose up -d
# Test your changes
docker-compose logs -f
```

## Security Guidelines

### NEVER Commit Secrets

- Always check for secrets before committing
- Use `.env` files (already in `.gitignore`)
- Use `.env.example` for templates with placeholder values
- Review changes with `git diff` before committing

### Protected Files

Never commit:
- `.env` files
- Database credentials
- API keys or tokens
- SSL certificates/private keys
- Real IP addresses or network details

### Security Best Practices

- Validate all user input
- Use parameterized queries (prevent SQL injection)
- Sanitize output (prevent XSS)
- Use HTTPS in production
- Follow OWASP Top 10 guidelines

## Pull Request Process

1. Ensure your code follows the style guide
2. Run linting and formatting
3. Test your changes thoroughly
4. Update documentation if needed
5. Create a pull request to the `main` branch
6. Fill out the PR template completely
7. Wait for code review

### PR Checklist

- [ ] Code follows project style guidelines
- [ ] All tests pass
- [ ] Documentation updated (if needed)
- [ ] No secrets or sensitive data committed
- [ ] Commit messages follow conventional format
- [ ] PR targets `main` branch

## Code Review

All submissions require review. We use GitHub pull requests for this purpose.

Reviewers will check for:
- Code quality and style
- Security issues
- Performance concerns
- Documentation completeness
- Test coverage

## Built-in Content Guidelines

### Adding Parsers

When adding built-in parsers:
- Use clear, descriptive names
- Provide detailed descriptions
- Include test samples
- Document the log format it parses
- Set appropriate priority (lower = higher priority)

### Adding Detection Rules

When adding built-in rules:
- Use descriptive names
- Provide clear descriptions
- Set appropriate severity levels
- Add relevant tags
- Test against sample logs
- Document false positive scenarios

## Documentation

- Update README.md for user-facing changes
- Update PLAN.md for architectural changes
- Add inline comments for complex logic
- Document all API endpoints
- Provide examples in documentation

## Questions?

- Open an issue for questions
- Join discussions on GitHub Discussions
- Check existing issues and PRs

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
