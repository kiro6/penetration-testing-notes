# Content
- [Database Commanda](#database-commanda)
- [Collection Commands](#collection-commands)
   - [General](#general)
   - [Count](#count)
   - [Insert](#insert)
   - [Read](#read)
   - [Update](#update)
   - [Replace](#replace)
   - [Delete](#delete)
   - [Indexes](#indexes)
- [Data Types](#data-types)
- [Operators](#operators)



## Database Commanda

```js
// show data bases
show dbs

// create or switch to databse
use appdb

// drop databse
db.dropDatabase()
```

## Collection Commands

### General
```js
// show collection
show collections

// create collection
db.createCollection('usernames')

// rename collection
db.<old_collection_name>.renameCollection("<new_collection_name>")


// Create collection with a $jsonschema
db.createCollection("contacts", {
   validator: {$jsonSchema: {
      bsonType: "object",
      required: ["phone"],
      properties: {
         phone: {
            bsonType: "string",
            description: "must be a string and is required"
         },
         email: {
            bsonType: "string",
            pattern: "@mongodb\.com$",
            description: "must be a string and match the regular expression pattern"
         },
         status: {
            enum: [ "Unknown", "Incomplete" ],
            description: "can only be one of the enum values"
         }
      }
   }}
})


db.coll.stats()
db.coll.storageSize()
db.coll.totalIndexSize()
db.coll.totalSize()
db.coll.validate({full: true})
db.coll.renameCollection("new_coll", true) // 2nd parameter to drop the target collection if exists

```
### Count
```js

// Count
db.coll.countDocuments({age: 32}) // alias for an aggregation pipeline - accurate count
db.coll.estimatedDocumentCount()  // estimation based on collection metadata
```
### Insert
```js
// insert
db.coll.insertOne({name: "Max"})
db.coll.insertMany([{name: "Max"}, {name:"Alex"}]) // ordered bulk insert
db.coll.insertMany([{name: "Max"}, {name:"Alex"}], {ordered: false}) // unordered bulk insert
db.coll.insertOne({date: ISODate()})
db.coll.insertOne({name: "Max"}, {"writeConcern": {"w": "majority", "wtimeout": 5000}})
```

### Read
```js

// Read
db.coll.findOne() // returns a single document
db.coll.find()    // returns a cursor - show 20 results - "it" to display more
db.coll.find().pretty()
db.coll.find({name: "Max", age: 32}) // implicit logical "AND".
db.coll.find({date: ISODate("2020-09-25T13:57:17.180Z")})
db.coll.distinct("name") // return an array of unique names present in the "name" field across all documents in the collection.


// Comparison
db.coll.find({"year": {$gt: 1970}})
db.coll.find({"year": {$gte: 1970}})
db.coll.find({"year": {$lt: 1970}})
db.coll.find({"year": {$lte: 1970}})
db.coll.find({"year": {$ne: 1970}})
db.coll.find({"year": {$in: [1958, 1959]}})
db.coll.find({"year": {$nin: [1958, 1959]}})


// Logical
db.coll.find({name:{$not: {$eq: "Max"}}})
db.coll.find({$or: [{"year" : 1958}, {"year" : 1959}]})
db.coll.find({$nor: [{price: 1.99}, {sale: true}]})
db.coll.find({
  $and: [
    {$or: [{qty: {$lt :10}}, {qty :{$gt: 50}}]},
    {$or: [{sale: true}, {price: {$lt: 5 }}]}
  ]
})


// Element
db.coll.find({name: {$exists: true}})
db.coll.find({"zipCode": {$type: 2 }})
db.coll.find({"zipCode": {$type: "string"}})


// Projections
db.coll.find({"x": 1}, {"actors": 1})               // actors + _id
db.coll.find({"x": 1}, {"actors": 1, "_id": 0})     // actors
db.coll.find({"x": 1}, {"actors": 0, "summary": 0}) // all but "actors" and "summary"

// Text search with a "text" index
db.products.find(
  {$text: {$search: "cake"}},
  {score: {$meta: "textScore"}}
).sort({score: {$meta: "textScore"}})


// regex
db.coll.find({name: /^Max/}) // regex: starts with "Max"
db.coll.find({name: /^Max$/i}) // regex case insensitive

// Sort, skip, limit

db.coll.find({}) // Retrieves all documents from the collection

.sort({"year": 1, "rating": -1}) //  sorts the documents first by the "year" field in ascending order (1) and then by the "rating" field in descending order (-1).

.skip(10) // Skips the first 10 documents

.limit(3) // Limits the result to 3 documents

```

### Update
```js
// single update
// Update a Document: Set "year" to 2016 and "name" to "Max" where _id = 1
db.coll.updateOne({"_id": 1}, {$set: {"year": 2016, name: "Max"}})

// Unset a Field: Remove "year" field from the document where _id = 1
db.coll.updateOne({"_id": 1}, {$unset: {"year": 1}})

// Rename a Field: Rename "year" to "date" where _id = 1
db.coll.updateOne({"_id": 1}, {$rename: {"year": "date"} })

// Increment a Numeric Field: Increment "year" by 5 where _id = 1
db.coll.updateOne({"_id": 1}, {$inc: {"year": 5}})

// Multiply Numeric Fields: Multiply "price" by 1.25 and "qty" by 2 where _id = 1
db.coll.updateOne({"_id": 1}, {$mul: {price: NumberDecimal("1.25"), qty: 2}})

// Set a Minimum Value for a Field: Set "imdb" to 5 if less than 5 where _id = 1
db.coll.updateOne({"_id": 1}, {$min: {"imdb": 5}})

// Set a Maximum Value for a Field: Set "imdb" to 8 if greater than 8 where _id = 1
db.coll.updateOne({"_id": 1}, {$max: {"imdb": 8}})

// Set Current Date: Set "lastModified" to current date and time where _id = 1
db.coll.updateOne({"_id": 1}, {$currentDate: {"lastModified": true}})

// Set Current Date with Type: Set "lastModified" to current timestamp where _id = 1
db.coll.updateOne({"_id": 1}, {$currentDate: {"lastModified": {$type: "timestamp"}}})


// updateMany
db.students.updateMany(
  { "name": /^A/ }, // Filter: Match all documents where the name starts with 'A'
  { $set: { "grade": "A+" } } // Update: Set the grade to 'A+'
)



// array
// Push a value to an array field. Adds the value 1 to the "array" field in the document with "_id" equal to 1
db.coll.updateOne({"_id": 1}, {$push: {"array": 1}})

// Pull a value from an array field. Removes the value 1 from the "array" field in the document with "_id" equal to 1
db.coll.updateOne({"_id": 1}, {$pull: {"array": 1}})

// Add a value to an array if it doesn't already exist. Adds the value 2 to the "array" field in the document with "_id" equal to 1 if it doesn't already exist
db.coll.updateOne({"_id": 1}, {$addToSet: {"array": 2}})

// Remove the last element from an array. Removes the last element from the "array" field in the document with "_id" equal to 1
db.coll.updateOne({"_id": 1}, {$pop: {"array": 1}})

// Remove the first element from an array. Removes the first element from the "array" field in the document with "_id" equal to 1
db.coll.updateOne({"_id": 1}, {$pop: {"array": -1}})

// Remove multiple values from an array. Removes the values 3, 4, and 5 from the "array" field in the document with "_id" equal to 1
db.coll.updateOne({"_id": 1}, {$pullAll: {"array": [3, 4, 5]}})

// Push multiple values to an array. Adds the values 90 and 92 to the "scores" field in the document with "_id" equal to 1
db.coll.updateOne({"_id": 1}, {$push: {"scores": {$each: [90, 92]}}})

// Push and sort multiple values to an array. Adds the values 40 and 60 to the "scores" field in the document with "_id" equal to 2 and sorts the array in ascending order
db.coll.updateOne({"_id": 2}, {$push: {"scores": {$each: [40, 60], $sort: 1}}})

// Update a specific element in an array. Updates the first element in the "grades" array with a value of 82 where the existing value is 80
db.coll.updateOne({"_id": 1, "grades": 80}, {$set: {"grades.$": 82}})

// Increment all elements in an array. Increments all elements in the "grades" array by 10 in all documents
db.coll.updateMany({}, {$inc: {"grades.$[]": 10}})

// Update elements in an array based on a condition

db.students.updateMany(
  {}, // Condition: Match all documents
  { $set: { "grades.$[element]": 100 } }, // Update: Set all grades greater than or equal to 100 to 100
  { 
    multi: true, // Update multiple documents
    arrayFilters: [ { "element": { $gte: 100 } } ] // Array filter to match grades greater than or equal to 100
  }
)

```
### Replace
```js
// Insert an example document into the collection
db.students.insertOne({
  "_id": 1,
  "name": "Alice",
  "grade": "A"
})


// New document to replace the existing one
var newDocument = {
  "_id": 1,
  "name": "Alice",
  "grade": "A+"
}

// Replace the existing document with the new one
db.students.replaceOne(
  { "_id": 1 }, // Filter: Match the document with _id equal to 1
  newDocument // New document to replace the existing one
)


```

### Delete
```js
db.coll.deleteOne({name: "Max"})
db.coll.deleteMany({name: "Max"}, {"writeConcern": {"w": "majority", "wtimeout": 5000}})
db.coll.deleteMany({}) // WARNING! Deletes all the docs but not the collection itself and its index definitions
db.coll.findOneAndDelete({"name": "Max"})
```

### Indexes
```js
db.coll.getIndexes()
db.coll.getIndexKeys()

// Index Types
db.coll.createIndex({"name": 1})                // single field index
db.coll.createIndex({"name": 1, "date": 1})     // compound index
db.coll.createIndex({foo: "text", bar: "text"}) // text index
db.coll.createIndex({"$**": "text"})            // wildcard text index
db.coll.createIndex({"userMetadata.$**": 1})    // wildcard index
db.coll.createIndex({"loc": "2d"})              // 2d index
db.coll.createIndex({"loc": "2dsphere"})        // 2dsphere index
db.coll.createIndex({"_id": "hashed"})          // hashed index

// Index Options
db.coll.createIndex({"lastModifiedDate": 1}, {expireAfterSeconds: 3600})      // TTL index
db.coll.createIndex({"name": 1}, {unique: true})
db.coll.createIndex({"name": 1}, {partialFilterExpression: {age: {$gt: 18}}}) // partial index
db.coll.createIndex({"name": 1}, {collation: {locale: 'en', strength: 1}})    // case insensitive index with strength = 1 or 2
db.coll.createIndex({"name": 1 }, {sparse: true})

// Drop Indexes
db.coll.dropIndex("name_1")

// Hide Indexes
db.coll.hideIndex("name_1")
db.coll.unhideIndex("name_1")
```


## Data Types

```
1: Double
2: String
3: Object
4: Array
5: Binary data
6: Undefined
7: ObjectId
8: Boolean
9: Date
10: Null
11: Regular Expression
12: DBPointer
13: JavaScript
14: Symbol
15: JavaScript (with scope)
16: 32-bit integer
17: Timestamp
18: 64-bit integer
19: Decimal128
-1: MinKey
127: MaxKey
```

## Operators
### Comparison Operators:
- **$eq**: Matches values that are equal to a specified value.
- **$ne**: Matches all values that are not equal to a specified value.
- **$gt**: Matches values that are greater than a specified value.
- **$gte**: Matches values that are greater than or equal to a specified value.
- **$lt**: Matches values that are less than a specified value.
- **$lte**: Matches values that are less than or equal to a specified value.
- **$in**: Matches any of the values specified in an array.
- **$nin**: Matches none of the values specified in an array.
- **$exists**: Matches documents that contain the specified field.

### Logical Operators:
- **$and**: Joins query clauses with a logical AND.
- **$or**: Joins query clauses with a logical OR.
- **$not**: Inverts the effect of a query expression.
- **$nor**: Joins query clauses with a logical NOR.
- **$where**: Matches documents based on JavaScript expression.

### Element Operators:
- **$exists**: Matches documents that contain the specified field.
- **$type**: Selects documents if a field is of the specified type.

### Array Operators:
- **$all**: Matches arrays that contain all elements specified in an array.
- **$elemMatch**: Selects documents if the array field contains at least one element that matches all the specified criteria.
- **$size**: Selects documents if the array field is a specified size.
- **$push**: Adds an item to an array field.
- **$addToSet**: Adds elements to an array field only if they do not already exist.
- **$pull**: Removes all array elements that match a specified query.
- **$pop**: Removes the first or last item of an array.
- **$pullAll**: Removes all matching values from an array.
- **$each**: Modifies a $push or $addToSet operation to append multiple values.

### Update Operators:
- **$set**: Sets the value of a field in a document.
- **$unset**: Removes the specified field from a document.
- **$inc**: Increments the value of a field by a specified amount.
- **$push**: Appends a specified value to an array.
- **$addToSet**: Adds elements to an array field only if they do not already exist.
- **$pop**: Removes the first or last item of an array.
- **$pull**: Removes all array elements that match a specified query.

### Text Search Operators:
- **$text**: Performs a text search.
- **$meta**: Projects the text score associated with the matching document.
