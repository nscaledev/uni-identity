# Identity API Integration Tests

The identity service includes API integration tests.

## Test Configuration

Tests are configured via environment variables using a `.env` file in the `test/` directory.

### Setup

1. **Set up your environment configuration:**

   Copy the example config and update with your values:
   ```bash
   cp test/.env.example test/.env
   ```

   Or create environment-specific files (not tracked in git):
   ```bash
   # Create .env.dev with your dev credentials
   cp test/.env.example test/.env.dev
   # Edit test/.env.dev with dev values

   # Create .env.uat with your UAT credentials
   cp test/.env.example test/.env.uat
   # Edit test/.env.uat with UAT values

   # Use the appropriate environment
   cp test/.env.dev test/.env    # For dev environment
   cp test/.env.uat test/.env    # For UAT environment
   ```

2. **Configure the required values in `test/.env`:**
   - `IDENTITY_BASE_URL` - Identity API server URL
   - `API_AUTH_TOKEN` - Service token from console
   - `TEST_ORG_ID`, `TEST_PROJECT_ID` - Test organization and project IDs

**Note:** All `test/.env` and `test/.env.*` files are gitignored and contain sensitive credentials. They should never be committed to the repository.

## Running Tests Locally

Run from project root:

**Run all tests:**
```bash
make test-api
```

**Run tests with verbose output:**
```bash
make test-api-verbose
```

**Run specific test suite using focus:**
```bash
# Example: Run only organization discovery tests
make test-api-focus FOCUS="Organization Discovery"
```

**Run specific test spec using focus:**
```bash
# Example: Run only the return all organizations test spec
make test-api-focus FOCUS="should return all accessible organizations"
```

**Run tests in parallel:**
```bash
make test-api-parallel
```

## Cleaning Up Test Artifacts

Remove test artifacts:
```bash
make test-api-clean
```
