# Plugin Example: Parse a pom.xml file and generate an SPDX 2.3 JSON document

## Writing the Plugin

In this example, we will parse an example pom.xml file and create an SPDX document with the data. The plugin is called `mvnpom`. We use an existing pom.xml parser to get the data. We have restricted parsing to only SPDX 2.3 as the SPDX version and JSON as the data format, but other versions and formats can be supported.

The required function to implement for the plugin is the `GetSpdxDocument` method. This must return an object of type `AnyDocument`.

In order to make this plugin "discoverable", the `init` function must be implemented. This function should use the `plugin` module's `Register` function, giving the name of the plugin. In this case, the name is "mvnpom".

## Using the Plugin

In the `main.go` program, we use an empty import to import the plugin `mvnpom`. We first get the plugin object. Then we call the object's `GetSpdxDocument()` function. From here we can create a JSON string using the `Marshal` function which takes care of creating an SPDX JSON document.
