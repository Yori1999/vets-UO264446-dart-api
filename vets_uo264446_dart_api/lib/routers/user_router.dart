import 'dart:convert';import 'package:shelf/shelf.dart';
import 'package:shelf_router/shelf_router.dart';
import 'package:vets_uo264446_dart_api/models/user.dart';
import 'package:vets_uo264446_dart_api/repositories/user_repository.dart';

final userRouter = Router()
  ..get('/users', _usersHandler)
  ..post('/users/signUp', _signUpHandler);

Future<Response> _usersHandler(Request request) async {
  final users = await UsersRepository.findAll();
  return Response.ok(json.encode(users));
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

