<?php

use Config\Services;
use Firebase\JWT\JWT;
use App\Models\UserModel;

// Comprobar en el encabezador de autorizacion 
function getJWTFromRequest($authenticationHeader): string
{
    if (is_null($authenticationHeader)) {
        // retorna un excepcion 404
        throw new Exception('Missing or invalid JWT in request');
    }
    // devolvemos el token
    return explode(' ', $authenticationHeader)[1];
}

// Toma el token obtenido y lo decodifica
function validateJWTFromRequest(string $encodedToken)
{
    $key = Services::getSecretKey();
    $decodedToken = JWT::decode($encodedToken, $key, ['HS256']);
    $userModel = new UserModel();
    $userModel->findUserByEmailAddress($decodedToken->email);
}

// Genera un token para un usuario con [email, emisión, expiración]
function getSignedJWTForUser(string $email): string
{
    $issuedAtTime = time();
    $tokenTimeToLive = getenv('JWT_TIME_TO_LIVE');
    $tokenExpiration = $issuedAtTime + $tokenTimeToLive;
    $payload = [
        'email' => $email,
        'iat' => $issuedAtTime,
        'exp' => $tokenExpiration
    ];

    $jwt = JWT::encode($payload, Services::getSecretKey());

    return $jwt;
}