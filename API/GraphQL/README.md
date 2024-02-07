# Content

## GraphQL schema
- the schema represents a contract between the frontend and backend of the service. 
- It defines the data available as a series of types
- The `!` operator indicates that the field is non-nullable when called (that is, mandatory). 
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
