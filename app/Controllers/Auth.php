<?php

namespace App\Controllers;

use App\Controllers\BaseController;

use CodeIgniter\HTTP\ResponseInterface;
use App\Models\UserModel;
use Exception;

class Auth extends BaseController
{
  public function register()
  {
    //Creamos reglas de validación
    $rules = [
      'name' => 'required',
      'email' => 'required|valid_email|is_unique[user.email]',
      'password' => 'required|min_length[8]|max_length[255]'
    ];
    // Usamos la funcion que creamos en el controlador base
    // Capturamos los datos de usuarios
    $input = $this->getRequestInput($this->request);
    // Validamos si se cumplen las reglas
    if (!$this->validateRequest($input, $rules)) {
      return $this->getResponse($this->validator->getErrors(), ResponseInterface::HTTP_BAD_REQUEST);
    }
    // nueva instancia al modelo de usuario
    $userModel = new UserModel();
    // Almacenamos el nuevo registro en db
    $userModel->save($input);
    // Retornamos la información con el token para el nuevo registro
    return $this->getJWTForUser($input['email'], ResponseInterface::HTTP_CREATED);
  }

  // funcion para iniciar seccion
  public function login()
  {
    //Creamos reglas de validación.
    // validateUser es una validación personalizada.
    $rules = [
      'email' => 'required|min_length[6]|max_length[50]|valid_email',
      'password' => 'required|min_length[8]|max_length[255]|validateUser[email, password]'
    ];

    // Mensaje de error en caso de que nuestra valicacion personalizada falle
    $errors = [
      'password' => [
        'validateUser' => 'Invalid login credentials provided'
      ]
    ];

    // Usamos la funcion que creamos en el controlador base
    // Capturamos los datos de usuarios
    $input = $this->getRequestInput($this->request);
    // Validamos si se cumplen las reglas
    if (!$this->validateRequest($input, $rules, $errors)) {
      return $this->getResponse($this->validator->getErrors(), ResponseInterface::HTTP_BAD_REQUEST);
    }
    // Retornamos la información con el token para el incio de session 
    return $this->getJWTForUser($input['email']);
  }

  // Obtener el jwt token para el usuario que se este intentando registrarse o loguearse
  private function getJWTForUser(string $email, int $responseCode = ResponseInterface::HTTP_OK)
  {
    try {
      $model = new UserModel();
      $user = $model->findUserByEmailAddress($email);
      unset($user['password']);
      helper('jwt');
      return $this->getResponse([
        'message' => 'User authented successfully',
        'user' => $user,
        'access_token' => getSignedJWTForUser($email)
      ]);
    } catch (Exception $e) {
      return $this->getResponse([
        'error' => $e->getMessage()
      ], $responseCode);
    }
  }
}
