<?php

function loadDatabaseSettings($pathjs){
        $string = file_get_contents($pathjs);
        $json_a = json_decode($string, true);
        return $json_a;
}

function getToken(){
        return bin2hex(random_bytes(32));
}

function jsonResponse($data, $statusCode = 200){
        http_response_code($statusCode);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($data, JSON_UNESCAPED_UNICODE);
}

function getJsonBody($f3){
        $body = $f3->get('BODY');
        $data = json_decode($body, true);

        if (!is_array($data) || json_last_error() !== JSON_ERROR_NONE) {
                return null;
        }

        return $data;
}

function hasRequiredFields($data, $fields){
        foreach ($fields as $field) {
                if (!array_key_exists($field, $data)) {
                        return false;
                }
        }

        return true;
}

function isValidString($value, $minLength = 1, $maxLength = 255){
        if (!is_string($value)) {
                return false;
        }

        $value = trim($value);
        $length = mb_strlen($value);

        return $length >= $minLength && $length <= $maxLength;
}

function isValidUsername($value){
        if (!isValidString($value, 3, 50)) {
                return false;
        }

        return preg_match('/^[a-zA-Z0-9_.-]+$/', $value) === 1;
}

function isValidEmailAddress($value){
        if (!isValidString($value, 5, 254)) {
                return false;
        }

        return filter_var($value, FILTER_VALIDATE_EMAIL) !== false;
}

function isValidPasswordForRegister($value){
        return is_string($value) && strlen($value) >= 8 && strlen($value) <= 128;
}

function isValidPasswordForLogin($value){
        return is_string($value) && strlen($value) >= 1 && strlen($value) <= 128;
}

function isValidToken($value){
        if (!is_string($value)) {
                return false;
        }

        return preg_match('/^[a-f0-9]{64}$/i', $value) === 1;
}

function isValidPositiveInteger($value){
        if (is_int($value)) {
                return $value > 0;
        }

        if (!is_string($value) && !is_numeric($value)) {
                return false;
        }

        return preg_match('/^[1-9][0-9]*$/', (string)$value) === 1;
}

function isValidImageName($value){
        if (!isValidString($value, 1, 100)) {
                return false;
        }

        return preg_match('/^[a-zA-Z0-9 _.-]+$/', $value) === 1;
}

function isValidImageExtension($value){
        if (!is_string($value)) {
                return false;
        }

        $allowed = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
        return in_array(strtolower($value), $allowed, true);
}

function isValidBase64($value){
        if (!is_string($value) || $value === '') {
                return false;
        }

        $decoded = base64_decode($value, true);

        if ($decoded === false) {
                return false;
        }

        $maxBytes = 5 * 1024 * 1024;

        return strlen($decoded) <= $maxBytes;
}

function getDatabaseConnection(){
        $dbcnf = loadDatabaseSettings('db.json');
        $db = new DB\SQL(
                'mysql:host=localhost;port='.$dbcnf['port'].';dbname='.$dbcnf['dbname'],
                $dbcnf['user'],
                $dbcnf['password']
        );
        $db->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

        return $db;
}

require 'vendor/autoload.php';

$f3 = \Base::instance();

/*
$f3->route('GET /',
        function() {
                echo 'Hello, world!';
        }
);
$f3->route('GET /saludo/@nombre',
        function($f3) {
                echo 'Hola '.$f3->get('PARAMS.nombre');
        }
);
*/

/*
 * Este Registro recibe un JSON con el siguiente formato
 *
 * {
 *              "uname": "XXX",
 *              "email": "XXX",
 *              "password": "XXX"
 * }
 */

$f3->route('POST /Registro',
        function($f3) {
                $jsB = getJsonBody($f3);

                if ($jsB === null || !hasRequiredFields($jsB, ['uname', 'email', 'password'])) {
                        jsonResponse(['R' => -1, 'D' => 'JSON inválido o campos obligatorios faltantes'], 400);
                        return;
                }

                $uname = trim($jsB['uname']);
                $email = trim($jsB['email']);
                $password = $jsB['password'];

                if (!isValidUsername($uname)) {
                        jsonResponse(['R' => -1, 'D' => 'Nombre de usuario inválido'], 422);
                        return;
                }

                if (!isValidEmailAddress($email)) {
                        jsonResponse(['R' => -1, 'D' => 'Correo electrónico inválido'], 422);
                        return;
                }

                if (!isValidPasswordForRegister($password)) {
                        jsonResponse(['R' => -1, 'D' => 'La contraseña debe tener entre 8 y 128 caracteres'], 422);
                        return;
                }

                try {
                        $db = getDatabaseConnection();
                        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

                        $R = $db->exec(
                                'insert into Usuario values(null,:uname,:email,:password)',
                                array(
                                        ':uname' => $uname,
                                        ':email' => $email,
                                        ':password' => $passwordHash
                                )
                        );
                } catch (Exception $e) {
                        jsonResponse(['R' => -2, 'D' => 'No fue posible registrar el usuario'], 409);
                        return;
                }

                jsonResponse(['R' => 0, 'D' => $R]);
        }
);

/*
 * Este Login recibe un JSON con el siguiente formato
 *
 * {
 *              "uname": "XXX",
 *              "password": "XXX"
 * }
 *
 * Debe retornar un Token
 */

$f3->route('POST /Login',
        function($f3) {
                $jsB = getJsonBody($f3);

                if ($jsB === null || !hasRequiredFields($jsB, ['uname', 'password'])) {
                        jsonResponse(['R' => -1, 'D' => 'JSON inválido o campos obligatorios faltantes'], 400);
                        return;
                }

                $uname = trim($jsB['uname']);
                $password = $jsB['password'];

                if (!isValidUsername($uname) || !isValidPasswordForLogin($password)) {
                        jsonResponse(['R' => -1, 'D' => 'Credenciales con formato inválido'], 422);
                        return;
                }

                try {
                        $db = getDatabaseConnection();

                        $R = $db->exec(
                                'Select id,password from Usuario where uname = :uname;',
                                array(
                                        ':uname' => $uname
                                )
                        );
                } catch (Exception $e) {
                        jsonResponse(['R' => -2, 'D' => 'Error al consultar el usuario'], 500);
                        return;
                }

                if (empty($R)){
                        jsonResponse(['R' => -3, 'D' => 'Credenciales inválidas'], 401);
                        return;
                }

                if (!password_verify($password, $R[0]['password'])) {
                        jsonResponse(['R' => -3, 'D' => 'Credenciales inválidas'], 401);
                        return;
                }

                $T = getToken();

                try {
                        $db->exec(
                                'Delete from AccesoToken where id_Usuario = :id_usuario;',
                                array(
                                        ':id_usuario' => $R[0]['id']
                                )
                        );

                        $db->exec(
                                'insert into AccesoToken values(:id_usuario,:token,now())',
                                array(
                                        ':id_usuario' => $R[0]['id'],
                                        ':token' => $T
                                )
                        );
                } catch (Exception $e) {
                        jsonResponse(['R' => -2, 'D' => 'Error al generar el token'], 500);
                        return;
                }

                jsonResponse(['R' => 0, 'D' => $T]);
        }
);

/*
 * Este subirimagen recibe un JSON con el siguiente formato
 *
 * {
 *              "token": "XXX",
 *              "name": "XXX",
 *              "data": "XXX",
 *              "ext": "PNG"
 * }
 *
 * Debe retornar codigo de estado
 */

$f3->route('POST /Imagen',
        function($f3) {
                $jsB = getJsonBody($f3);

                if ($jsB === null || !hasRequiredFields($jsB, ['name', 'data', 'ext', 'token'])) {
                        jsonResponse(['R' => -1, 'D' => 'JSON inválido o campos obligatorios faltantes'], 400);
                        return;
                }

                $name = trim($jsB['name']);
                $data = $jsB['data'];
                $ext = strtolower(trim($jsB['ext']));
                $TKN = trim($jsB['token']);

                if (!isValidToken($TKN)) {
                        jsonResponse(['R' => -1, 'D' => 'Token inválido'], 422);
                        return;
                }

                if (!isValidImageName($name)) {
                        jsonResponse(['R' => -1, 'D' => 'Nombre de imagen inválido'], 422);
                        return;
                }

                if (!isValidImageExtension($ext)) {
                        jsonResponse(['R' => -1, 'D' => 'Extensión de imagen no permitida'], 422);
                        return;
                }

                if (!isValidBase64($data)) {
                        jsonResponse(['R' => -1, 'D' => 'Contenido base64 inválido o demasiado grande'], 422);
                        return;
                }

                if (!file_exists('tmp')) {
                        mkdir('tmp', 0750);
                }

                if (!file_exists('img')) {
                        mkdir('img', 0750);
                }

                try {
                        $db = getDatabaseConnection();

                        $R = $db->exec(
                                'select id_Usuario from AccesoToken where token = :token',
                                array(
                                        ':token' => $TKN
                                )
                        );
                } catch (Exception $e) {
                        jsonResponse(['R' => -2, 'D' => 'Error al validar token'], 500);
                        return;
                }

                if (empty($R)) {
                        jsonResponse(['R' => -3, 'D' => 'Token no autorizado'], 401);
                        return;
                }

                $id_Usuario = $R[0]['id_Usuario'];
                $tmpPath = 'tmp/'.$id_Usuario;

                file_put_contents($tmpPath, base64_decode($data, true));

                try {
                        $db->exec(
                                'insert into Imagen values(null,:name,"img/",:id_usuario);',
                                array(
                                        ':name' => $name,
                                        ':id_usuario' => $id_Usuario
                                )
                        );

                        $R = $db->exec(
                                'select max(id) as idImagen from Imagen where id_Usuario = :id_usuario',
                                array(
                                        ':id_usuario' => $id_Usuario
                                )
                        );

                        $idImagen = $R[0]['idImagen'];
                        $rutaImagen = 'img/'.$idImagen.'.'.$ext;

                        $db->exec(
                                'update Imagen set ruta = :ruta where id = :id_imagen',
                                array(
                                        ':ruta' => $rutaImagen,
                                        ':id_imagen' => $idImagen
                                )
                        );

                        rename($tmpPath, $rutaImagen);
                } catch (Exception $e) {
                        if (file_exists($tmpPath)) {
                                unlink($tmpPath);
                        }

                        jsonResponse(['R' => -2, 'D' => 'Error al guardar imagen'], 500);
                        return;
                }

                jsonResponse(['R' => 0, 'D' => $idImagen]);
        }
);

/*
 * Este Descargar recibe un JSON con el siguiente formato
 *
 * {
 *              "token": "XXX",
 *              "id": "XXX"
 * }
 */

$f3->route('POST /Descargar',
        function($f3) {
                $jsB = getJsonBody($f3);

                if ($jsB === null || !hasRequiredFields($jsB, ['token', 'id'])) {
                        jsonResponse(['R' => -1, 'D' => 'JSON inválido o campos obligatorios faltantes'], 400);
                        return;
                }

                $TKN = trim($jsB['token']);
                $idImagen = $jsB['id'];

                if (!isValidToken($TKN)) {
                        jsonResponse(['R' => -1, 'D' => 'Token inválido'], 422);
                        return;
                }

                if (!isValidPositiveInteger($idImagen)) {
                        jsonResponse(['R' => -1, 'D' => 'ID de imagen inválido'], 422);
                        return;
                }

                try {
                        $db = getDatabaseConnection();

                        $R = $db->exec(
                                'select id_Usuario from AccesoToken where token = :token',
                                array(
                                        ':token' => $TKN
                                )
                        );
                } catch (Exception $e) {
                        jsonResponse(['R' => -2, 'D' => 'Error al validar token'], 500);
                        return;
                }

                if (empty($R)) {
                        jsonResponse(['R' => -3, 'D' => 'Token no autorizado'], 401);
                        return;
                }

                try {
                        $R = $db->exec(
                                'Select name,ruta from Imagen where id = :id_imagen',
                                array(
                                        ':id_imagen' => $idImagen
                                )
                        );
                }catch (Exception $e) {
                        jsonResponse(['R' => -3, 'D' => 'Error al buscar imagen'], 500);
                        return;
                }

                if (empty($R) || !file_exists($R[0]['ruta'])) {
                        jsonResponse(['R' => -4, 'D' => 'Imagen no encontrada'], 404);
                        return;
                }

                $web = \Web::instance();
                ob_start();
                $info = pathinfo($R[0]['ruta']);
                $web->send($R[0]['ruta'], NULL, 0, TRUE, $R[0]['name'].'.'.$info['extension']);
                ob_get_clean();
        }
);
