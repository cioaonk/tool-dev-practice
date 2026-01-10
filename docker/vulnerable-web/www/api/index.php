<?php
header('Content-Type: application/json');

$endpoints = [
    'status' => '/api/status',
    'users' => '/api/users',
    'version' => '/api/version',
    'config' => '/api/config',
    'health' => '/api/health'
];

echo json_encode([
    'service' => 'CPTC11 API',
    'version' => '1.0.0',
    'endpoints' => $endpoints,
    'status' => 'operational'
], JSON_PRETTY_PRINT);
