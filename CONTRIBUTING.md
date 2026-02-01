# Contributing to Imladris

Thank you for your interest in contributing to the Imladris Zero Trust Banking Platform!

## 🚀 Quick Start for Contributors

### Prerequisites

Ensure you have the following installed:
- Terraform >= 1.0
- AWS CLI >= 2.31
- Conftest >= 0.46
- Go >= 1.21 (for service template)

### Development Workflow

1. **Fork and Clone**
   ```bash
   git clone https://github.com/YOUR-USERNAME/imladris-project.git
   cd imladris-project
   ```

2. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Changes**
   - Follow existing code patterns
   - Add tests where applicable
   - Update documentation

4. **Validate Changes**
   ```bash
   # Terraform validation
   cd imladris-platform
   terraform init
   terraform validate
   terraform fmt -recursive
   
   # Policy validation
   cd ../imladris-governance
   conftest verify -p policies/
   ```

5. **Commit with Conventional Commits**
   ```bash
   git commit -m "feat: add new feature description"
   git commit -m "fix: resolve issue description"
   git commit -m "docs: update documentation"
   git commit -m "chore: maintenance task"
   ```

6. **Push and Create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

## 📋 Pull Request Guidelines

### Before Submitting

- [ ] `terraform validate` passes
- [ ] `terraform fmt` applied
- [ ] `conftest test` passes (if modifying infrastructure)
- [ ] Documentation updated (if applicable)
- [ ] No secrets or credentials in code

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Refactoring

## Testing
How were changes tested?

## Checklist
- [ ] terraform validate passes
- [ ] terraform fmt applied
- [ ] Documentation updated
```

## 🏗️ Code Structure Guidelines

### Terraform Modules

```
modules/
└── my-module/
    ├── main.tf          # Primary resources
    ├── variables.tf     # Input variables with descriptions
    ├── outputs.tf       # Output values
    └── README.md        # Module documentation
```

### Naming Conventions

| Resource | Convention | Example |
|----------|------------|---------|
| Terraform resources | snake_case | `aws_eks_cluster.main` |
| Variables | snake_case | `cluster_name` |
| Outputs | snake_case | `cluster_endpoint` |
| Tags | PascalCase | `Name`, `Environment` |

### Policy Files (Rego)

- One policy per file
- Clear `deny` or `warn` rule names
- Include test files (`*_test.rego`)

## 🛡️ Security Guidelines

- Never commit credentials or secrets
- Use variables for sensitive values
- Follow least-privilege IAM principles
- All security groups must have descriptions

## 📝 Documentation

- Update README.md for significant changes
- Add inline comments for complex logic
- Document all module variables

## 🐛 Bug Reports

Include:
1. Description of the issue
2. Steps to reproduce
3. Expected vs actual behavior
4. Terraform version
5. AWS region (if applicable)

## 💬 Questions?

Open a GitHub Discussion or Issue for questions about contributing.

---

Thank you for helping improve Imladris! 🙏
