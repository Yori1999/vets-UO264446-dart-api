import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';

class UserTokenService {
  final String _secret;

  UserTokenService(this._secret);

  static String generateJwt(Map<String, dynamic> payload) {
    final jwt = JWT(payload);
    // Sign it
    final key = SecretKey('secret passphrase');
    // El token expira en 120 segundos
    final Duration expiresIn = Duration(minutes: 2);
    final String token = jwt.sign(key, expiresIn: expiresIn);
    return token;
  }

  static Map<String, dynamic> verifyJwt(String token) {
    if (token.isEmpty) {
      return {"authorized": false, "error": "El Token no existe o está vacío"};
    }
    try {
      final key = SecretKey('secret passphrase');
      final jwt = JWT.verify(token, key);
      Map<String, dynamic> infoToken = jwt.payload;
      infoToken.addAll({"authorized": true});
      return jwt.payload;
    } on JWTExpiredError {
      return {"authorized": false, "error": "El Token ha caducado"};
    } on JWTError {
      return {"authorized": false, "error": "Firma inválida"};
    }
  }
}