# Content
- [GraphQL datatypes](#graphql-datatypes)
- [GraphQL schema](#graphql-schema)
- [GraphQL queries](#graphql-queries)
- [GraphQL mutations](#graphql-mutations)
- [Components of queries and mutations](#components-of-queries-and-mutations)
  - [Variables](#variables)
  - [Aliases](#aliases)
  - [Fragments](#fragments)
- [Introspection](#introspection)

## GraphQL datatypes
| Type          | Description                                                |
|---------------|------------------------------------------------------------|
| Int           | A signed 32-bit integer.                                   |
| Float         | A signed double-precision floating-point value.            |
| String        | A UTF-8 character sequence.                                |
| Boolean       | `true` or `false`.                                         |
| ID            | Represents a unique identifier. Serialized like a String.  |

| Type          | Description                                                |
|---------------|------------------------------------------------------------|
| Object types | Represent a group of fields with name and value type.      |
| Enum types    | Scalar type restricted to a particular set of allowed values. |
| List types    | Represent arrays of values, holding multiple items of the same type. |
| NonNull types | Represent a type that cannot be null.                      |




## GraphQL schema
- the schema represents a contract between the frontend and backend of the service. 
- It defines the data available as a series of types
- The `!` operator indicates that the field is non-nullable when called (that is, mandatory).
- `[]` This indicates that the field returns an array or list.
- `:` This define the return type
```graphql
type Post {
  id: ID!
  title: String!
  content: String!
  author: User!
  comments: [Comment!]!
}

type User {
  id: ID!
  name: String!
  email: String!
  posts: [Post!]!
}

type Comment {
  id: ID!
  content: String!
  author: User!
  post: Post!
}

type Query {
  posts: [Post!]!
  post(id: ID!): Post
  users: [User!]!
  user(id: ID!): User
}

type Mutation {
  createPost(title: String!, content: String!, authorId: ID!): Post!
  createUser(name: String!, email: String!): User!
  createComment(content: String!, authorId: ID!, postId: ID!): Comment!
}

```

## GraphQL queries

**GraphQL query contain**
- A query operation type. This is technically optional but encouraged, as it explicitly tells the server that the incoming request is a query.
- A query name. This can be anything you want. The query name is optional, but encouraged as it can help with debugging.
- A data structure. This is the data that the query should return.
- Optionally, one or more arguments.

```graphql
query GetPosts {   # Query name: GetPosts
  posts {          # Query operation: Query
    id             # Data structure: id of each post
    title          # Data structure: title of each post
    author {       # Data structure: information about the author of each post
      id           # Data structure: id of the author
      name         # Data structure: name of the author
    }
  }
}

query GetPostById($postId: ID!) {  # Query name: GetPostById, with an argument postId
  post(id: $postId) {              # Query operation: Query, with an argument id
    id
    title
    content
    author {
      id
      name
    }
    comments {
      id
      content
      author {
        id
        name
      }
    }
  }
}


```
## GraphQL mutations
- Mutations change data in some way, either adding, deleting, or editing it

**Mutation Request:**
```graphql
mutation CreateUser {
  createUser(name: "John Doe", email: "john@example.com") {
    id
    name
    email
  }
}
```
**Mutation Response:**
```json
{
  "data": {
    "createUser": {
      "id": "123",
      "name": "John Doe",
      "email": "john@example.com"
    }
  }
}
```
##  Components of queries and mutations 

### Variables
- use `$` to define a variable

variables with mutation
```graphql
mutation CreateUser($name: String!, $email: String!) {
  createUser(name: $name, email: $email) {
    id
    name
    email
  }
}

Variables:
    {
          "name": "John Doe",
          "email": "john@example.com"
    }
```

variables with query
```graphql
query GetPost($postId: ID!) {
  post(id: $postId) {
    title
    content
  }
}

Variables:
{
  "postId": "your_post_id_here"
}

```
### Aliases
```graphql
query GetTwoPosts {
  firstPost: post(id: "post_id_1") {
    title
    content
  }
  secondPost: post(id: "post_id_2") {
    title
    content
  }
}

```

### Fragments
- Fragments are reusable parts of queries or mutations.
- use `...` to call a fragment

```graphql
query GetTwoPosts {
  firstPost: post(id: "post_id_1") {
    ...PostFields
  }
  secondPost: post(id: "post_id_2") {
    ...PostFields
  }
}

fragment PostFields on Post {
  title
  content
}

```
## Introspection

- Introspection is a built-in GraphQL function that enables you to query a server for information about the schema.

introspection request
```graphql
query IntrospectionQuery {
  __schema {
    types {
      name
      description
      kind
      fields {
        name
        description
        args {
          name
          description
          type {
            name
            kind
            ofType {
              name
              kind
            }
          }
          defaultValue
        }
      }
      enumValues {
        name
        description
      }
      possibleTypes {
        name
      }
    }
  }
}

```
