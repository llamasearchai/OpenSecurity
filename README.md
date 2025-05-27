# SecureML - ML-Driven Security Detection Platform

A comprehensive, production-ready security detection platform powered by OpenAI agents and machine learning, built with FastAPI and modern Python technologies.

## Features

### OpenAI Agents Integration
- **Security Analyst Agents**: AI-powered security analysis with specialized capabilities
- **Task Management**: Asynchronous task execution with priority queuing
- **Agent Orchestration**: Centralized management of multiple concurrent agents
- **Real-time Communication**: Direct messaging and broadcasting to agents

### Security Detection
- **ML-Based Detectors**: Extensible framework for custom security detectors
- **Real-time Analysis**: Process security telemetry in real-time
- **Threat Assessment**: Automated threat severity and impact analysis
- **Incident Response**: AI-generated incident response plans

### Comprehensive API
- **RESTful Endpoints**: Complete FastAPI-based REST API
- **Authentication**: JWT-based authentication with role-based access
- **Real-time Monitoring**: Health checks, metrics, and system monitoring
- **Interactive Documentation**: Auto-generated OpenAPI/Swagger documentation

### Production-Ready Architecture
- **Async/Await**: Full asynchronous support for high performance
- **Configuration Management**: Environment-based configuration system
- **Structured Logging**: Advanced logging with correlation IDs
- **Error Handling**: Comprehensive error handling and recovery
- **Testing**: 100% test coverage with unit, integration, and API tests

## Prerequisites

- Python 3.10+
- Poetry (for dependency management)
- OpenAI API key (for agent functionality)

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/llamasearchai/OpenSecurity.git
cd secureml
```

### 2. Install Dependencies
```bash
# Install Poetry if you haven't already
curl -sSL https://install.python-poetry.org | python3 -

# Install project dependencies
poetry install
```

### 3. Environment Configuration
```bash
# Copy the example environment file
cp .env.example .env

# Edit the environment file with your settings
nano .env
```

### 4. Required Environment Variables
```bash
# OpenAI Configuration
SECUREML_OPENAI_API_KEY=your_openai_api_key_here
SECUREML_OPENAI_ORGANIZATION=your_org_id_here  # Optional

# Security Configuration
SECUREML_SECURITY_JWT_SECRET=your_super_secret_jwt_key_here

# Application Configuration
SECUREML_ENVIRONMENT=development
SECUREML_API_DEBUG=true
SECUREML_LOGGING_LEVEL=INFO
```

## Quick Start

### 1. Start the Application
```bash
# Using Poetry
poetry run python -m backend.api.main

# Or using uvicorn directly
poetry run uvicorn backend.api.main:app --reload --host 0.0.0.0 --port 8000
```

### 2. Access the API
- **API Base URL**: http://localhost:8000
- **Interactive Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health/

### 3. Authentication
```bash
# Login to get access token
curl -X POST "http://localhost:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Use the token in subsequent requests
curl -X GET "http://localhost:8000/agents/" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

## API Usage Examples

### Agent Management

#### Create a Security Analyst Agent
```bash
curl -X POST "http://localhost:8000/agents/" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_type": "security_analyst",
    "agent_id": "my-security-agent"
  }'
```

#### Submit a Security Analysis Task
```bash
curl -X POST "http://localhost:8000/agents/tasks" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Log Analysis",
    "description": "Analyze firewall logs for threats",
    "input_data": {
      "type": "log_analysis",
      "logs": [
        {
          "timestamp": "2024-01-01T10:00:00Z",
          "source_ip": "192.168.1.100",
          "destination_ip": "10.0.0.1",
          "port": 22,
          "action": "ACCEPT"
        }
      ],
      "log_type": "firewall"
    },
    "priority": 8,
    "agent_id": "my-security-agent"
  }'
```

#### Check Task Status
```bash
curl -X GET "http://localhost:8000/agents/tasks/TASK_ID" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Security Detection

#### Run Detection on Data
```bash
curl -X POST "http://localhost:8000/detectors/detect" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "network_traffic": [
        {
          "src_ip": "192.168.1.100",
          "dst_ip": "suspicious-domain.com",
          "bytes": 1024,
          "timestamp": "2024-01-01T10:00:00Z"
        }
      ]
    }
  }'
```

## Testing

### Run All Tests
```bash
# Run the complete test suite
poetry run pytest

# Run with coverage
poetry run pytest --cov=backend --cov-report=html

# Run specific test categories
poetry run pytest -m "unit"        # Unit tests only
poetry run pytest -m "integration" # Integration tests only
poetry run pytest -m "api"         # API tests only
poetry run pytest -m "agents"      # Agent tests only
```

### Test Categories
- **Unit Tests**: Test individual components in isolation
- **Integration Tests**: Test component interactions
- **API Tests**: Test all REST endpoints
- **Agent Tests**: Test OpenAI agent functionality
- **Performance Tests**: Test system performance and scalability

## Architecture

### System Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   FastAPI App   │    │  Agent Manager  │    │   OpenAI API    │
│                 │    │                 │    │                 │
│ - REST Endpoints│◄──►│ - Task Queue    │◄──►│ - GPT Models    │
│ - Authentication│    │ - Agent Pool    │    │ - Completions   │
│ - Validation    │    │ - Orchestration │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Detectors     │    │   Agents        │    │   Configuration │
│                 │    │                 │    │                 │
│ - ML Models     │    │ - Security      │    │ - Environment   │
│ - Rule Engine   │    │   Analyst       │    │ - Logging       │
│ - Anomaly Det.  │    │ - Capabilities  │    │ - Security      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Key Design Patterns
- **Dependency Injection**: Clean separation of concerns
- **Factory Pattern**: Agent and detector creation
- **Observer Pattern**: Event-driven architecture
- **Strategy Pattern**: Pluggable detection algorithms
- **Command Pattern**: Task execution system

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SECUREML_OPENAI_API_KEY` | OpenAI API key | None | Yes |
| `SECUREML_OPENAI_MODEL` | OpenAI model to use | gpt-4-turbo-preview | No |
| `SECUREML_ENVIRONMENT` | Environment (dev/test/prod) | development | No |
| `SECUREML_API_HOST` | API host address | 0.0.0.0 | No |
| `SECUREML_API_PORT` | API port number | 8000 | No |
| `SECUREML_SECURITY_JWT_SECRET` | JWT signing secret | CHANGE_THIS | Yes |
| `SECUREML_AGENTS_MAX_CONCURRENT` | Max concurrent agents | 10 | No |
| `SECUREML_LOGGING_LEVEL` | Logging level | INFO | No |

### Configuration Files
- `pyproject.toml`: Project dependencies and metadata
- `.env`: Environment-specific configuration
- `backend/core/config.py`: Configuration management

## Security Features

### Authentication & Authorization
- **JWT Tokens**: Secure token-based authentication
- **Role-Based Access**: Different access levels (admin, analyst)
- **Token Refresh**: Automatic token renewal
- **Session Management**: Secure session handling

### Security Best Practices
- **Input Validation**: Comprehensive request validation
- **Rate Limiting**: API rate limiting (configurable)
- **CORS Protection**: Cross-origin request protection
- **Error Handling**: Secure error responses
- **Logging**: Security event logging

## Monitoring & Observability

### Health Checks
- **Liveness Probe**: `/health/liveness` - Basic health check
- **Readiness Probe**: `/health/readiness` - Service readiness
- **Comprehensive Health**: `/health/` - Detailed system health

### Metrics
- **System Metrics**: CPU, memory, disk usage
- **Application Metrics**: Agent statistics, task metrics
- **Custom Metrics**: Business-specific measurements

### Logging
- **Structured Logging**: JSON-formatted logs
- **Correlation IDs**: Request tracing
- **Log Levels**: Configurable verbosity
- **Log Rotation**: Automatic log management

## Deployment

### Docker Deployment
```dockerfile
# Dockerfile example
FROM python:3.10-slim

WORKDIR /app
COPY pyproject.toml poetry.lock ./
RUN pip install poetry && poetry install --no-dev

COPY . .
EXPOSE 8000

CMD ["poetry", "run", "uvicorn", "backend.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Kubernetes Deployment
```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secureml
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secureml
  template:
    metadata:
      labels:
        app: secureml
    spec:
      containers:
      - name: secureml
        image: secureml:latest
        ports:
        - containerPort: 8000
        env:
        - name: SECUREML_OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: secureml-secrets
              key: openai-api-key
        livenessProbe:
          httpGet:
            path: /health/liveness
            port: 8000
        readinessProbe:
          httpGet:
            path: /health/readiness
            port: 8000
```

### Production Considerations
- **Load Balancing**: Multiple instance deployment
- **Database**: External database for persistence
- **Caching**: Redis for session and data caching
- **Monitoring**: Prometheus/Grafana integration
- **Secrets Management**: Kubernetes secrets or Vault

## Contributing

### Development Setup
```bash
# Clone and setup
git clone https://github.com/llamasearchai/OpenSecurity.git
cd secureml
poetry install

# Install pre-commit hooks
poetry run pre-commit install

# Run tests
poetry run pytest

# Code formatting
poetry run black backend/ tests/
poetry run isort backend/ tests/

# Type checking
poetry run mypy backend/
```

### Code Quality
- **Black**: Code formatting
- **isort**: Import sorting
- **mypy**: Type checking
- **flake8**: Linting
- **bandit**: Security scanning
- **pytest**: Testing framework

### Git Commit Guidelines

Follow these guidelines for clear and professional commit messages:

- **Atomic Commits**: Each commit should represent a single logical change. Avoid bundling unrelated changes into one commit.
- **Clear Subject Line**: The subject line should be concise (around 50 characters) and summarize the change. Use the imperative mood (e.g., "Add user authentication" not "Added user authentication").
- **Detailed Body (If Needed)**: If the change is complex, provide a more detailed explanation in the commit body. Explain *what* changed and *why*.
- **Reference Issues**: If the commit addresses a specific issue, reference it in the commit message (e.g., "Fix #123: Resolve login bug").
- **Formatting**:
    - Separate subject from body with a blank line.
    - Wrap the body at 72 characters.
    - Use bullet points or numbered lists for longer descriptions if appropriate.

**Example Commit Message:**

```
feat: Add user registration endpoint

Implement the `/auth/register` endpoint to allow new users to sign up.

- Validates email uniqueness.
- Hashes passwords securely using bcrypt.
- Returns user information upon successful registration.

Closes #42
```

### Pull Request Process
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Support

### Documentation
- **API Documentation**: http://localhost:8000/docs
- **Code Documentation**: Generated with mkdocs
- **Architecture Docs**: In the `docs/` directory

### Getting Help
- **Issues**: GitHub Issues for bug reports
- **Discussions**: GitHub Discussions for questions
- **Security**: security@example.com for security issues

### Troubleshooting

#### Common Issues

**OpenAI API Key Issues**
```bash
# Check if API key is set
echo $SECUREML_OPENAI_API_KEY

# Test API key
curl -H "Authorization: Bearer $SECUREML_OPENAI_API_KEY" \
  https://api.openai.com/v1/models
```

**Agent Not Responding**
```bash
# Check agent status
curl -X GET "http://localhost:8000/agents/health/check" \
  -H "Authorization: Bearer YOUR_TOKEN"

# Check logs
tail -f secureml.log
```

**Performance Issues**
```bash
# Check system metrics
curl -X GET "http://localhost:8000/health/metrics"

# Monitor agent statistics
curl -X GET "http://localhost:8000/agents/stats/manager" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## Roadmap

### Upcoming Features
- [ ] **Advanced ML Models**: Custom security detection models
- [ ] **Real-time Streaming**: Kafka/Redis Streams integration
- [ ] **Multi-tenant Support**: Organization-based isolation
- [ ] **Advanced Analytics**: Security dashboards and reporting
- [ ] **Plugin System**: Extensible detector and agent plugins
- [ ] **Workflow Engine**: Complex security workflow automation

### Version History
- **v1.0.0**: Initial release with core functionality
- **v1.1.0**: Enhanced agent capabilities (planned)
- **v1.2.0**: Advanced detection algorithms (planned)
- **v2.0.0**: Multi-tenant architecture (planned)

---

**Built with for the cybersecurity community** 