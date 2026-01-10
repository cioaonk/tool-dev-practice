"""
Docker Integration Tests for CPTC11 Security Tools
===================================================

This module contains integration tests that run against the Docker
test environment defined in /Users/ic/cptc11/docker/

Prerequisites:
    - Docker and docker-compose installed
    - Docker environment running: docker-compose up -d
    - Tests should be run from project root

Usage:
    pytest python/tests/docker_integration/ -v

Environment Variables:
    DOCKER_HOST: Override Docker host (default: localhost)
    SKIP_DOCKER_TESTS: Set to skip Docker integration tests
"""
