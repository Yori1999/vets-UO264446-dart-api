import 'dart:convert';import 'package:shelf/shelf.dart';
import 'package:shelf_router/shelf_router.dart';
import 'package:vets_uo264446_dart_api/models/user.dart';
import 'package:vets_uo264446_dart_api/repositories/user_repository.dart';
import 'package:vets_uo264446_dart_api/encrypt_password.dart'as encrypter;
import 'package:vets_uo264446_dart_api/user_token_service.dart' as jwt_service;
import 'package:mongo_dart/mongo_dart.dart';

final userRouter = Router()
  ..get('/users', _usersHandler)
  ..post('/users/signUp', _signUpHandler)
  ..post('/users/login', _loginHandler)
  ..get('/users/<id>', _getUserHandler)
  ..delete('/users/<id>', _deleteUserHandler);

/** Función manejadora del login */

Future<Response> _loginHandler(Request request) async {
  final credentialRequestBody = await request.readAsString();
  final Map<String, dynamic> bodyParams = json.decode(credentialRequestBody);
  // Verificamos que las credenciales vengan en el body de la petición
  final String email = bodyParams.containsKey('email') ? bodyParams['email'] : '';
  final String password = bodyParams.containsKey('password') ? bodyParams['password'] : '';

  // Creamos las credenciales con la contraseña cifrada, porque en la base de datos se almacena cifrada
  final Map<String, dynamic> credentials = {
    "email" : email,
    "password" : password
  };

  final authorizedUser = await areCredentialsValid(credentials);

  if (!authorizedUser) {
    return Response.unauthorized(json.encode({
      "message" : "Usuario no autorizado o credenciales inválidas",
      "authenticated" : false
    }));
  } else {
    String token = jwt_service.UserTokenService.generateJwt({"email" : email});
    return Response.ok(json.encode({
      "message" : "Usuario autorizado",
      "authenticated" : true,
      "token" : token
    }));
  }
}

Future<bool> areCredentialsValid(Map<String, dynamic> credentials) async {
  final user = await UsersRepository.findOne({"email" : credentials["email"]});
  if (user != null) {
    final encryptedPass = encrypter.checkPassword(credentials["password"], user["password"]);
    return encryptedPass;
  } else {
    return false;
  }
}

/** Fin de la función manejadora del login */

Future<Response> _deleteUserHandler(Request request) async {
  final dynamic token = request.headers.containsKey("token") ? request.headers["token"] : "";
  final Map<String, dynamic> verifiedToken = jwt_service.UserTokenService.verifyJwt(token);
  if (verifiedToken['authorized'] == false) {
    return Response.unauthorized(json.encode(verifiedToken));
  } else {
    dynamic userId = ObjectId.fromHexString(request.params['id'].toString());
    dynamic result = await UsersRepository.deleteOne({"_id" : userId});
    if (result.nRemoved < 1) {
      return Response.notFound('Usuario no encontrado');
    } else {
      return Response.ok('Usuario $userId eliminado correctamente');
    }
  }
}

Future<Response> _getUserHandler(Request request) async {
  final dynamic token = request.headers.containsKey("token") ? request.headers["token"] : "";
  final Map<String, dynamic> verifiedToken = jwt_service.UserTokenService.verifyJwt(token);
  if (verifiedToken['authorized'] == false) {
    return Response.unauthorized(json.encode(verifiedToken));
  } else {
    dynamic userId = ObjectId.fromHexString(request.params['id'].toString());
    final users = await UsersRepository.findOne({"_id" : userId});
    return Response.ok(json.encode(users));
  }
}

Future<Response> _usersHandler(Request request) async {
  final dynamic token = request.headers.containsKey("token") ? request.headers["token"] : "";
  final Map<String, dynamic> verifiedToken = jwt_service.UserTokenService.verifyJwt(token);
  if (verifiedToken['authorized'] == false) {
    return Response.unauthorized(json.encode(verifiedToken));
  } else {
    final users = await UsersRepository.findAll();
    return Response.ok(json.encode(users));
  }
}

Future<Response> _signUpHandler(Request request) async {
  final userRequestBody = await request.readAsString();
  final user = User.fromJson(json.decode(userRequestBody));
  final List<Map<String, String>> userValidateErrors = await validateUser(user);
  dynamic userCreated;
  if (userValidateErrors.isEmpty) {
    userCreated = await UsersRepository.insertOne(user);
    // if hubo un error al insertar el registro
    if (userCreated.containsKey("error")) userValidateErrors.add(userCreated);
  }
  if (userValidateErrors.isNotEmpty) {
    final encodedError = jsonEncode(userValidateErrors);
    return Response.badRequest(
        body: encodedError, headers: {'content-type': 'application/json'});
  } else {
    return Response.ok('Usuario creado correctamente $userCreated');
  }
}

validateUser(User user) async {
  List<Map<String, String>> errors = [];
  final userFound = await UsersRepository.findOne({"email": user.email});

  if (userFound != null) {
    errors.add({"email": "The user already exists with the same email"});
  }
  if (user.email.isEmpty) {
    errors.add({"email": "Email is a required field"});
  }
  if (user.name.isEmpty) {
    errors.add({"name": "Name is a required field"});
  }
  if (user.surname.isEmpty) {
    errors.add({"surname": "surname is a required field"});
  }
  if (user.password.isEmpty || user.password.length < 6) {
    errors.add({"surname": "Password should have at least 6 characters"});
  }
  
  return errors;
}

