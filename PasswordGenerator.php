<?php

/**
 * PasswordGenerator — clase que encapsula la lógica de generación segura.
 * Usa random_int() para entropía criptográfica y Fisher–Yates para el shuffle.
 */
class PasswordGenerator
{
    // Conjuntos base
    private const UPPER   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    private const LOWER   = 'abcdefghijklmnopqrstuvwxyz';
    private const DIGITS  = '0123456789';
    private const SYMBOLS = '!@#$%^&*()-_=+[]{}|;:,.<>?';
    private const AMBIGUOUS = 'Il1O0o';

    // Restricciones globales
    public const MIN_LENGTH = 4;
    public const MAX_LENGTH = 128;

    // -----------------------------------------------------------------------
    // Métodos privados de utilidad
    // -----------------------------------------------------------------------

    private function shuffleSecure(string $str): string
    {
        $arr = preg_split('//u', $str, -1, PREG_SPLIT_NO_EMPTY);
        $n   = count($arr);
        for ($i = $n - 1; $i > 0; $i--) {
            $j       = random_int(0, $i);
            [$arr[$i], $arr[$j]] = [$arr[$j], $arr[$i]];
        }
        return implode('', $arr);
    }

    private function buildSets(array $opts): array
    {
        $sets = [];
        if ($opts['upper'])   $sets['upper']   = self::UPPER;
        if ($opts['lower'])   $sets['lower']   = self::LOWER;
        if ($opts['digits'])  $sets['digits']  = self::DIGITS;
        if ($opts['symbols']) $sets['symbols'] = self::SYMBOLS;

        if (empty($sets)) {
            throw new InvalidArgumentException(
                'Debe activarse al menos una categoría (upper/lower/digits/symbols).'
            );
        }

        // Construir mapa de exclusiones
        $excludeStr = $opts['exclude'];
        if ($opts['avoid_ambiguous']) {
            $excludeStr .= self::AMBIGUOUS;
        }
        $excludeMap = array_flip(
            array_unique(preg_split('//u', $excludeStr, -1, PREG_SPLIT_NO_EMPTY))
        );

        // Filtrar cada set
        foreach ($sets as $key => $chars) {
            $filtered = implode('', array_filter(
                preg_split('//u', $chars, -1, PREG_SPLIT_NO_EMPTY),
                fn($c) => !isset($excludeMap[$c])
            ));
            if ($filtered === '') {
                throw new InvalidArgumentException(
                    "Después de aplicar exclusiones, la categoría '{$key}' no tiene caracteres disponibles."
                );
            }
            $sets[$key] = $filtered;
        }

        return $sets;
    }

    // -----------------------------------------------------------------------
    // API pública
    // -----------------------------------------------------------------------

    /**
     * Genera una sola contraseña.
     */
    public function generate(int $length, array $opts = []): string
    {
        if ($length < self::MIN_LENGTH || $length > self::MAX_LENGTH) {
            throw new InvalidArgumentException(
                "La longitud debe estar entre " . self::MIN_LENGTH . " y " . self::MAX_LENGTH . " caracteres."
            );
        }

        $opts = array_merge([
            'upper'           => true,
            'lower'           => true,
            'digits'          => true,
            'symbols'         => false,
            'avoid_ambiguous' => false,
            'exclude'         => '',
            'require_each'    => true,
        ], $opts);

        $sets = $this->buildSets($opts);
        $pool = implode('', array_values($sets));

        $chars = [];

        // Garantizar al menos 1 carácter por categoría
        if ($opts['require_each']) {
            foreach ($sets as $setChars) {
                $chars[] = $setChars[random_int(0, strlen($setChars) - 1)];
            }
        }

        // Rellenar hasta la longitud deseada
        $needed = $length - count($chars);
        for ($i = 0; $i < $needed; $i++) {
            $chars[] = $pool[random_int(0, strlen($pool) - 1)];
        }

        return $this->shuffleSecure(implode('', $chars));
    }

    /**
     * Genera múltiples contraseñas.
     */
    public function generateMany(int $count, int $length, array $opts = []): array
    {
        if ($count < 1 || $count > 100) {
            throw new InvalidArgumentException("El número de contraseñas debe estar entre 1 y 100.");
        }
        $passwords = [];
        for ($i = 0; $i < $count; $i++) {
            $passwords[] = $this->generate($length, $opts);
        }
        return $passwords;
    }

    /**
     * Valida la fortaleza de una contraseña según requisitos dados.
     */
    public function validate(string $password, array $requirements = []): array
    {
        $req = array_merge([
            'minLength'        => 8,
            'maxLength'        => self::MAX_LENGTH,
            'requireUppercase' => false,
            'requireLowercase' => false,
            'requireNumbers'   => false,
            'requireSymbols'   => false,
        ], $requirements);

        $checks  = [];
        $passed  = 0;
        $total   = 0;

        // Longitud mínima
        $total++;
        $lenOk = strlen($password) >= $req['minLength'];
        $checks['minLength'] = [
            'passed'  => $lenOk,
            'message' => "Mínimo {$req['minLength']} caracteres (tiene " . strlen($password) . ")",
        ];
        if ($lenOk) $passed++;

        // Longitud máxima
        $total++;
        $maxOk = strlen($password) <= $req['maxLength'];
        $checks['maxLength'] = [
            'passed'  => $maxOk,
            'message' => "Máximo {$req['maxLength']} caracteres",
        ];
        if ($maxOk) $passed++;

        // Mayúsculas
        if ($req['requireUppercase']) {
            $total++;
            $ok = (bool) preg_match('/[A-Z]/', $password);
            $checks['requireUppercase'] = ['passed' => $ok, 'message' => 'Debe contener al menos una mayúscula'];
            if ($ok) $passed++;
        }

        // Minúsculas
        if ($req['requireLowercase']) {
            $total++;
            $ok = (bool) preg_match('/[a-z]/', $password);
            $checks['requireLowercase'] = ['passed' => $ok, 'message' => 'Debe contener al menos una minúscula'];
            if ($ok) $passed++;
        }

        // Números
        if ($req['requireNumbers']) {
            $total++;
            $ok = (bool) preg_match('/[0-9]/', $password);
            $checks['requireNumbers'] = ['passed' => $ok, 'message' => 'Debe contener al menos un número'];
            if ($ok) $passed++;
        }

        // Símbolos
        if ($req['requireSymbols']) {
            $total++;
            $ok = (bool) preg_match('/[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]/', $password);
            $checks['requireSymbols'] = ['passed' => $ok, 'message' => 'Debe contener al menos un símbolo'];
            if ($ok) $passed++;
        }

        $score    = $total > 0 ? round(($passed / $total) * 100) : 100;
        $strength = match (true) {
            $score >= 100 => 'strong',
            $score >= 75  => 'moderate',
            $score >= 50  => 'weak',
            default       => 'very_weak',
        };

        return [
            'valid'    => $passed === $total,
            'score'    => $score,
            'strength' => $strength,
            'checks'   => $checks,
        ];
    }
}
