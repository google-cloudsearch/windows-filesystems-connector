# Google Cloud Search Windows File Systems Connector

The Google Cloud Search Windows File Systems Connector enables indexing Microsoft Windows File
Systems including SMB, DFS, and Windows File Share, with support for ACLs and instant change
detection. This connector implements the graph traversal strategy provided by the
[Content Connector SDK](https://developers.google.com/cloud-search/docs/guides/content-connector).

## Build instructions

1. Install the SDK into your local Maven repository

   a. Clone the SDK repository from GitHub:
      ```
      git clone https://github.com/google-cloudsearch/connector-sdk.git
      cd connector-sdk
      ```

   b. Checkout the desired version of the SDK:
      ```
      git checkout tags/v1-0.0.3
      ```

   c. Install the SDK components:
      ```
      mvn install
      ```

2. Build the connector

   a. Clone the connector repository from GitHub:
      ```
      git clone https://github.com/google-cloudsearch/windows-filesystems-connector.git
      cd windows-filesystems-connector
      ```

   b. Checkout the desired version of the connector and build the ZIP file:
      ```
      git checkout tags/v1-0.0.3
      mvn package
      ```
      (To skip the tests when building the connector, use `mvn package -DskipTests`)

3. Run the connector
   ```
   java \
      -jar target/google-cloudsearch-windows-filesystems-connector-v1-0.0.3.jar \
      -Dconfig=my.config
   ```

   Where `my.config` is the configuration file containing the parameters for the
   connector execution.

   **Note:** If the configuration file is not specified, a default file name of
   `connector-config.properties` will be assumed. Refer to the
   [configuration documentation](https://developers.google.com/cloud-search/docs/guides/filesystem-connector#specify-configuration)
   for specifics and for parameter details.

4. Install the connector

   To install the connector for testing or production, copy the ZIP file from the
   target directory to the desired machine and unzip it in the desired directory.

For further information on configuration and deployment of this connector, see
[Deploy the Microsoft Windows File Systems Connector](https://developers.google.com/cloud-search/docs/guides/filesystem-connector).
