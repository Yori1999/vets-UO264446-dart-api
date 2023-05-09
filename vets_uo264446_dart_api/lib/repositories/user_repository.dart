import 'package:vets_uo264446_dart_api/db_manager.dart';
import 'package:vets_uo264446_dart_api/encrypt_password.dart';
import 'package:vets_uo264446_dart_api/models/user.dart';

class UsersRepository {
  static DbManager dbManager = DbManager.collection("users");

  static Future<dynamic> insertOne(User user) async {
    String encriptedPassword = encryptPassword(user.password);
    user.password = encriptedPassword;
    final result = await dbManager.insertOne(user.toJsonInsert());
    return result;
  }

  static Future<dynamic> findAll() async {
    final result = await dbManager.findAll();
    return result;
  }

  static Future<dynamic> findOne(Map<String, dynamic> filter) async {
    final result = await dbManager.findOne(filter);
    return result;
  }

  static Future<dynamic> deleteOne(Map<String, dynamic> filter) async {
    final result = await dbManager.deleteOne(filter);
    return result;
  }

  static Future<dynamic> updateOne(Map<String, dynamic> filter, Map<String, dynamic> data) async {
    final result = await dbManager.updateOne(filter, data);
    return result;
  }

}