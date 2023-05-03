import 'package:bcrypt/bcrypt.dart';

String encryptPassword(String password) {
  final salt = BCrypt.gensalt();
  final hash = BCrypt.hashpw(password, salt);
  return hash;
}

bool checkPassword(String password, String hashed) {
  final bool checkPassword = BCrypt.checkpw(password, hashed);
  return checkPassword;
}
