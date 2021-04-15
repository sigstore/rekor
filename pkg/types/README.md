# Pluggable Types

## Description

Rekor supports pluggable types (aka different schemas) for entries stored in the transparency log.

### Currently supported types

- Rekord (default type) [schema](rekord/rekord_schema.json)
  - Versions: 0.0.1


## Base Schema

The base schema for all types is modeled off of the schema used by Kubernetes and can be found in `openapi.yaml` as `#/definitions/ProposedEntry`:

```
definitions:
  ProposedEntry:
    type: object
    discriminator: kind
    properties:
      kind:
        type: string
    required:
      - kind
```

The `kind` property is a [discriminator](https://github.com/OAI/OpenAPI-Specification/blob/master/versions/2.0.md#fixed-fields-13) that is used to differentiate between different pluggable types. Types can have one or more versions of the schema supported concurrently by the same Rekor instance; an example implementation can be seen in `rekord.go`.

## Adding Support for a New Type

To add a new type (called `newType` in this example):
1. Add a new definition in `openapi.yaml` that is a derived type of ProposedEntry (expressed in the `allOf` list seen below); for example:

```yaml
  newType:
    type: object
    description: newType object
    allOf:
    - $ref: '#/definitions/ProposedEntry'
    - properties:
        version:
          type: string
        metadata:
          type: object
          additionalProperties: true
        data:
          type: object
          $ref: 'pkg/types/newType/newType_schema.json'
      required:
        - version
        - data
      additionalProperties: false
```

> Note: the `$ref` feature can be used to refer to an externally defined JSON schema document; however it is also permitted to describe the entirety of the type in valid Swagger (aka OpenAPI) v2 format within `openapi.yaml`.

2. Create a subdirectory under `pkg/types/` with your type name (e.g. `newType`) as a new Go package

3. In this new Go package, define a struct that:
```go
type TypeImpl interface {
	UnmarshalEntry(pe models.ProposedEntry) (EntryImpl, error)
}
```
  - implements the `TypeImpl` interface as defined in `types.go`:
    - `UnmarshalEntry` will be called with a pointer to a struct that was automatically generated for the type defined in `openapi.yaml` by the [go-swagger](http://github.com/go-swagger/go-swagger) tool used by Rekor
      - This struct will be defined in the generated file at `pkg/generated/models/newType.go` (where `newType` is replaced with the name of the type you are adding)
      - This method should return a pointer to an instance of a struct that implements the `EntryImpl` interface as defined in `types.go`, or a `nil` pointer with an error specified
  - embedds the `RekorType` type into the struct definition 
    - The purpose of this is to set the Kind variable to match the type name
    - `RekorType` also includes a `VersionMap` field, which provides the lookup for a version string from a proposed entry to find the correct implmentation code

4. Also in this Go package, provide an implementation of the `EntryImpl` interface as defined in `types.go`:
```go
type EntryImpl interface {
	APIVersion() string
	IndexKeys() []string
	Canonicalize(ctx context.Context) ([]byte, error)
	FetchExternalEntities(ctx context.Context) error
	HasExternalEntities() bool
	Unmarshal(pe models.ProposedEntry) error
	Validate() error
}
```

  - `APIVersion` should return a version string that identifies the version of the type supported by the Rekor server
  - `IndexKeys` should return a `[]string` that extracts the keys from an entry to be stored in the search index
  - `Canonicalize` should return a `[]byte` containing the canonicalized contents representing the entry. The canonicalization of contents is important as we should have one record per unique signed object in the transparency log.
  - `FetchExternalEntities` should retrieve any entities that make up the entry which were not included in the object provided in the HTTP request to the Rekor server
  - `HasExternalEntities` indicates whether the instance of the struct has any external entities it has yet to fetch and resolve
  - `Unmarshal` will be called with a pointer to a struct that was automatically generated for the type defined in `openapi.yaml` by the [go-swagger](http://github.com/go-swagger/go-swagger) tool used by Rekor
    - This method should validate the contents of the struct to ensure any string or cross-field dependencies are met to successfully insert an entry of this type into the transparency log
  - `Validate` performs cross-field validation for fields in object that can not be expressed easily in the OpenAPI definition

5. In the Go package you have created for the new type, be sure to add an entry in the `TypeMap` in `github.com/sigstore/rekor/pkg/types` for your new type in the `init` method for your package. The key for the map is the unique string used to define your type in `openapi.yaml` (e.g. `newType`), and the value for the map is the name of a factory function for an instance of `TypeImpl`.

```go
func init() {
	types.TypeMap.Store("newType", NewEntry)
}
```

6. Add an entry to `pluggableTypeMap` in `cmd/server/app/serve.go` that provides a reference to your package. This ensures that the `init` function of your type (and optionally, your version implementation) will be called before the server starts to process incoming requests and therefore will be added to the map that is used to route request processing for different types.

7. After adding sufficient unit & integration tests, submit a pull request to `github.com/sigstore/rekor` for review and addition to the codebase.

## Adding a New Version of the `Rekord` type

To add new version of the default `Rekord` type:

1. Create a new subdirectory under `pkg/types/rekord/` for the new version

2. If there are changes to the Rekord schema for this version, create a new JSON schema document and add a reference to it within the `oneOf` clause in `rekord_schema.json`. If there are no changes, skip this step.

3. Provide an implementation of the `EntryImpl` interface as defined in `pkg/types/types.go` for the new version.

4. In your package's `init` method, ensure there is a call to `VersionMap.Store()` which provides the link between the valid *semver* ranges that your package can successfully process and the factory function that creates an instance of a struct for your new version.

5. Add an entry to `pluggableTypeMap` in `cmd/server/app/serve.go` that provides a reference to the Go package implementing the new version. This ensures that the `init` function will be called before the server starts to process incoming requests and therefore will be added to the map that is used to route request processing for different types.

6. After adding sufficient unit & integration tests, submit a pull request to `github.com/sigstore/rekor` for review and addition to the codebase.
