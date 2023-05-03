import 'package:bson/bson.dart';

class User {
  late ObjectId? id;
  String name;
  String surname;
  String email;
  DateTime birthDate;
  String password;

  User(this.id, this.name, this.surname, this.email, this.birthDate, this.password);

  // constructor para crear un usuario sin ID de mongo
  User.forInsert(this.name, this.surname, this.email, this.birthDate, this.password);

  Map<String, dynamic> toJsonInsert() => {
      'name': name,
      'surname': surname,
      'email': email,
      'birthDate': birthDate.toIso8601String(),
      'password': password
    };

  Map<String, dynamic> toJson() => {
      '_id': id,
      'name': name,
      'surname': surname,
      'email': email,
      'birthDate': birthDate.toIso8601String(),
      'password': password
    };    

  static User fromJson(Map<String, dynamic> json) => User(
    json.containsKey('_id') ? ObjectId.fromHexString(json['_id']) : null,
    json.containsKey('name') ? json['name'] : "",
    json.containsKey('surname') ? json['surname'] : "",
    json.containsKey('email') ? json['email'] : "",
    json.containsKey('birthDate') ? json['birthDate']: DateTime.now(),
    json.containsKey('password') ? json['password'] : "",
  );
}