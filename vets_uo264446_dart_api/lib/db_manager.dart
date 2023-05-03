import 'package:mongo_dart/mongo_dart.dart';

class DbManager {
  String _dbName = "vets-dart-api";
  String _collectionName = "users";
  late dynamic _collection;
  late Db _db;

  DbManager(String dbName, String collectionName) {
    _dbName = dbName;
    _collectionName = collectionName;
  }

  DbManager.collection(String collectionName) {
    _collectionName = collectionName;
  }

  Future<void> connect() async {
    final dbUrl =
        'mongodb+srv://uo264446:z4qQjbEIbD6Y75Si@cluster0.cu3jckq.mongodb.net/$_dbName?retryWrites=true&w=majority';

    _db = await Db.create(dbUrl);
    await _db.open();
    _collection = _db.collection(_collectionName);
    //return _db.collection(_collectionName);
  }

  Future<void> close() async {
    await _db.close();
  }

  Future<List<Map<String, dynamic>>> findAll() async {
    try {
      await connect();
      final data = await _collection.find().toList();
      return data;
    } catch (error) {
      List<Map<String, dynamic>> errorList = [];
      Map<String, dynamic> error = {
        "error": "Se ha producido un error al recuperar los datos"
      };
      errorList.add(error);
      return errorList;
    } finally {
      await close();
    }
  }

  Future<dynamic> insertOne(Map<String, dynamic> data) async {
    try {
      await connect();
      final result = await _collection.insertOne(data);
      if (result.isSuccess) {
        return {"insertedId": result.id};
      } else {
        return {"error": result.writeError.errmsg};
      }
    } catch (error) {
        return {"error": "Se ha producido un error inesperado"};
    } finally {
        await close();
    }
  }

  // Method findOne take the same parameter and returns Future of just one map (mongo document) or null if not found
  Future<dynamic> findOne(filter) async {
    await connect();
    final result = await _collection.findOne(filter);
    return result;
  }

}