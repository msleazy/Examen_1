<?php
/**
 * API REST — Generadora de Contraseñas Seguras
 *
 * Rutas:
 *   GET  /api/password          → genera una contraseña
 *   POST /api/passwords         → genera múltiples contraseñas
 *   POST /api/password/validate → valida fortaleza de una contraseña
 */

declare(strict_types=1);

require_once __DIR__ . '/PasswordGenerator.php';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function jsonResponse(mixed $data, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

function errorResponse(string $message, int $status = 400, array $details = []): void
{
    $body = ['error' => true, 'message' => $message, 'status' => $status];
    if ($details) {
        $body['details'] = $details;
    }
    jsonResponse($body, $status);
}

function getRequestBody(): array
{
    $raw = file_get_contents('php://input');
    if (empty($raw)) {
        return [];
    }
    $data = json_decode($raw, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        errorResponse('Cuerpo JSON inválido: ' . json_last_error_msg(), 400);
    }
    return $data ?? [];
}

function boolParam(mixed $value, bool $default = false): bool
{
    if (is_bool($value)) return $value;
    if (is_string($value)) return in_array(strtolower($value), ['true', '1', 'yes'], true);
    if (is_int($value)) return $value !== 0;
    return $default;
}

function intParam(mixed $value, int $default): int
{
    return is_numeric($value) ? (int) $value : $default;
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

$method  = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$rawPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
// Normalizar: quitar trailing slash
$path = rtrim($rawPath, '/');

$gen = new PasswordGenerator();

// ---- GET /api/password -------------------------------------------------------
if ($method === 'GET' && $path === '/api/password') {
    $length  = intParam($_GET['length'] ?? null, 16);
    $opts = [
        'upper'           => boolParam($_GET['includeUppercase']   ?? true, true),
        'lower'           => boolParam($_GET['includeLowercase']   ?? true, true),
        'digits'          => boolParam($_GET['includeNumbers']     ?? true, true),
        'symbols'         => boolParam($_GET['includeSymbols']     ?? false),
        'avoid_ambiguous' => boolParam($_GET['excludeAmbiguous']   ?? false),
        'exclude'         => (string) ($_GET['exclude']            ?? ''),
        'require_each'    => boolParam($_GET['requireEach']        ?? true, true),
    ];

    try {
        $password = $gen->generate($length, $opts);
        jsonResponse([
            'success'  => true,
            'password' => $password,
            'length'   => strlen($password),
            'options'  => $opts,
        ]);
    } catch (InvalidArgumentException $e) {
        errorResponse($e->getMessage(), 400);
    }
}

// ---- POST /api/passwords ------------------------------------------------------
elseif ($method === 'POST' && $path === '/api/passwords') {
    $body   = getRequestBody();
    $length = intParam($body['length'] ?? null, 16);
    $count  = intParam($body['count']  ?? null, 1);

    $opts = [
        'upper'           => boolParam($body['includeUppercase'] ?? true, true),
        'lower'           => boolParam($body['includeLowercase'] ?? true, true),
        'digits'          => boolParam($body['includeNumbers']   ?? true, true),
        'symbols'         => boolParam($body['includeSymbols']   ?? false),
        'avoid_ambiguous' => boolParam($body['excludeAmbiguous'] ?? false),
        'exclude'         => (string) ($body['exclude']          ?? ''),
        'require_each'    => boolParam($body['requireEach']      ?? true, true),
    ];

    try {
        $passwords = $gen->generateMany($count, $length, $opts);
        jsonResponse([
            'success'   => true,
            'count'     => count($passwords),
            'passwords' => $passwords,
            'length'    => $length,
            'options'   => $opts,
        ]);
    } catch (InvalidArgumentException $e) {
        errorResponse($e->getMessage(), 400);
    }
}

// ---- POST /api/password/validate -----------------------------------------------
elseif ($method === 'POST' && $path === '/api/password/validate') {
    $body = getRequestBody();

    if (empty($body['password']) || !is_string($body['password'])) {
        errorResponse("El campo 'password' es obligatorio y debe ser una cadena de texto.", 422);
    }

    $password     = $body['password'];
    $requirements = $body['requirements'] ?? [];

    // Mapeo de claves del examen → claves internas
    $req = [];
    if (isset($requirements['minLength']))        $req['minLength']        = intParam($requirements['minLength'], 8);
    if (isset($requirements['maxLength']))        $req['maxLength']        = intParam($requirements['maxLength'], 128);
    if (isset($requirements['requireUppercase'])) $req['requireUppercase'] = boolParam($requirements['requireUppercase']);
    if (isset($requirements['requireLowercase'])) $req['requireLowercase'] = boolParam($requirements['requireLowercase']);
    if (isset($requirements['requireNumbers']))   $req['requireNumbers']   = boolParam($requirements['requireNumbers']);
    if (isset($requirements['requireSymbols']))   $req['requireSymbols']   = boolParam($requirements['requireSymbols']);

    $result = $gen->validate($password, $req);

    jsonResponse([
        'success'  => true,
        'password' => $password,
        'result'   => $result,
    ], $result['valid'] ? 200 : 422);
}

// ---- 404 -------------------------------------------------------------------
else {
    errorResponse("Endpoint no encontrado: {$method} {$path}", 404);
}
