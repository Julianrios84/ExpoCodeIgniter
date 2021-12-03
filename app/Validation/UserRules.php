<?php

namespace App\Validation;
use App\Models\UserModel;

class UserRules
{
    // Definimos la validacion personalizada
    public function validateUser(string $str, string $fields, array $data): bool
    {
        // Verificamos si el usuario que se esta logueando
        // Si la contraseña enviada es correcta
        try {
            $model = new UserModel();
            $user = $model->findUserByEmailAddress($data['email']);
            return password_verify($data['password'], $user['password']);
        } catch (\Exception $e) {
            return false;
        }
    }
}
