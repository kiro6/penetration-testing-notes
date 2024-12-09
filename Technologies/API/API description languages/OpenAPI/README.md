
## OpenAPI Specification (OAS) :
- OpenAPI is a standard for describing and documenting RESTful APIs. It defines a set of rules and guidelines that developers and API providers can follow to create consistent and well-documented APIs.
- The primary goal of OpenAPI is to promote interoperability between different API tools and services.

## The OpenAPI Specification provides a machine-readable format (typically written in JSON or YAML) that describes various aspects of an API, including:

1. **Endpoints and Operations**: It defines the available endpoints, the supported HTTP methods (GET, POST, PUT, DELETE, etc.), and the parameters required for each operation.
    
2. **Data Formats**: It specifies the data formats (JSON, XML, etc.) that the API supports for both request payloads and response data.
    
3. **Authentication and Security**: It allows specifying the authentication methods required to access the API securely.
    
4. **Response Codes and Errors**: It documents the possible response codes, response data models, and error messages that the API might return.
    
5. **Request and Response Schemas**: It defines the structure of the request and response payloads using JSON Schema or other data modeling techniques.

### Example :
```yaml
openapi: 3.0.3
info:
  title: Pet Store API
  version: 1.0.0
  description: An example API for managing pets in a pet store.
  contact:
    name: Pet Store Support
    email: support@petstore.com
  license:
    name: MIT License
    url: https://opensource.org/licenses/MIT

servers:
  - url: https://api.petstore.com/v1
    description: Production server

paths:
  /pets:
    get:
      summary: Get all pets
      description: Returns a list of all pets in the store.
      operationId: getAllPets
      responses:
        '200':
          description: A list of pets.
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/Pet'
    post:
      summary: Add a new pet
      description: Adds a new pet to the store.
      operationId: addPet
      requestBody:
        description: The pet to add.
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/Pet'
      responses:
        '201':
          description: The newly added pet.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Pet'
        '400':
          description: Invalid input.

  /pets/{petId}:
    get:
      summary: Get a pet by ID
      description: Returns a single pet based on its ID.
      operationId: getPetById
      parameters:
        - name: petId
          in: path
          description: ID of the pet to retrieve.
          required: true
          schema:
            type: integer
      responses:
        '200':
          description: The pet with the specified ID.
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Pet'
        '404':
          description: Pet not found.

components:
  schemas:
    Pet:
      type: object
      properties:
        id:
          type: integer
          format: int64
        name:
          type: string
        species:
          type: string
        age:
          type: integer
          format: int32
      required:
        - name
        - species
```
